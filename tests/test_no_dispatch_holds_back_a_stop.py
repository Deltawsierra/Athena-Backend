"""No connector dispatch holds back a stop (#303).

A deployment whose dispatch policy opts into the decision trigger has its
qualifying findings pushed to its connectors when its decision becomes blocking --
and a pause is a blocking decision. The recompute route, which pauses and lifts,
scheduled that dispatch "on commit"; the route runs in autocommit, where a commit
hook runs at once, so the pause answered only after every finding had been pushed
to every connector. Measured on the release before: three findings and a
connector that takes five seconds to answer held a pause for 15.04 s, and a lift
or a plain recompute landing on a blocking decision for 15.05 s. The transport's
timeout is (3.05, 10) seconds a push, so a hung ticketing system held a pause for
thirteen seconds per finding.

Now the stop records the dispatch as owed in its own transaction, commits and
answers, and the dispatch runs after it, in the background. A run claims what it
runs, so two runners never push one deployment at once; it checks before every
push that the decision which asked for it still holds; and what it does not
finish -- or never starts, its process gone -- stays recorded until a run does.

The timing tests MEASURE it: the connector here holds every push until the test
lets it go, or three seconds pass, and the stop must answer in under a second with
no push finished. They do not assert the structure that should make it fast; they
assert that it is.
"""

from __future__ import annotations

import io
import logging
import os
import threading
import time
import uuid
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from django.contrib import admin as django_admin
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.db import DatabaseError, OperationalError, connections, transaction
from django.test import RequestFactory, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import dispatch
from assurance.claims import derive_claims
from assurance.decision import recompute_decision
from assurance.models import (
    Asset,
    AssuranceClaim,
    ConnectorBinding,
    DataBoundary,
    DecisionDispatchDue,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    Finding,
)

pytestmark = pytest.mark.django_db

User = get_user_model()

#: A stop alone takes milliseconds; the first request of a process pays for the
#: URLconf, which every test here pays before it measures.
PROMPT = 1.0
#: How long the connector holds a push the test has not let go of.
HOLD = 3.0

with_key = override_settings(ASSURANCE_CREDENTIAL_KEY=Fernet.generate_key().decode())


class _Answer:
    def __init__(self, status_code):
        self.status_code = status_code
        self.text = ""

    def json(self):
        return {"key": "SEC-1"} if self.status_code < 300 else {}


class HeldConnector:
    """A connector that holds every push until released (or ``HOLD`` passes), then
    answers ``status``. Counts the pushes it has finished."""

    def __init__(self, status=201):
        self.status = status
        self.release = threading.Event()
        self.started = 0
        self.finished = 0
        self.bodies = []
        self.headers = []
        self._lock = threading.Lock()

    def factory(self):
        return self

    def post(self, url, *, headers, json):
        with self._lock:
            self.started += 1
            self.bodies.append(repr(json))
            self.headers.append(dict(headers))
        self.release.wait(HOLD)
        with self._lock:
            self.finished += 1
        return _Answer(self.status)


class _Json:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body
        self.text = repr(body)

    def json(self):
        return self.body


class Crash(BaseException):
    """The runner's process dies here: nothing after this line of the run happens."""


class FakeRemote:
    """A system the findings are pushed to, as each connector's API sees it: a
    create by POST, a look-up by GET -- oldest issue first, a page at a time -- and
    a read of one issue by its id. Each issue keeps its creation time, its labels
    and its body (Jira's description, ServiceNow's description and
    ``correlation_display``), which is what the look verifies a marker against.

    - Jira: ``jira = "cloud"`` serves ``/rest/api/3/search/jql`` (paged by
      ``nextPageToken``, description as a document) and answers 410 on the retired
      ``/rest/api/2/search``; ``"dc"`` (Data Center / Server) serves only the
      latter (paged by ``startAt``) and answers 404 on the former. Both honour the
      JQL's project, ``labels in (...)`` and ``text ~ "..."``, and report each
      issue's status category and creation time.
    - GitHub: the issues list by label (``state`` open/closed/all, ``sort`` and
      ``direction``, ``page``/``per_page``), and the search in bodies. ``drop_labels``
      models a token without push access, whose labels GitHub silently drops.
    - ServiceNow: the table query on ``correlation_id``, ``ORDERBY`` honoured.
    - Each answers newest first unless asked for oldest first.
    - The webhook's receiver drops a second delivery of one ``Idempotency-Key``.
    - Comments are recorded. ``crash`` makes the runner die right after the system
      committed the next create, before the answer is back."""

    def __init__(self, jira="cloud"):
        self.issues = []
        self.creates = 0
        self.comments = []
        self.gets = []
        self.crash = False
        self.jira = jira
        self.drop_labels = False

    def factory(self):
        return self

    @staticmethod
    def _kind(url):
        if "/rest/api/" in url:
            return "jira"
        if "/repos/" in url:
            return "github"
        if "/api/now/table/" in url:
            return "servicenow"
        return "other"

    def add(self, ref, finding=None, *, closed=False, project="SEC", kind="jira", created=None, labels=None,
            body=None, display=None, correlation_id=None):
        """An issue already there. With ``finding``: one this installation created
        for it (its marker label, and the tag in its body); otherwise whatever
        ``labels``, ``body``, ``display`` and ``correlation_id`` say."""
        if finding is not None:
            marker = _ours(finding, {"github": "github_issues"}.get(kind, kind))
            labels = [marker.label] if labels is None else labels
            body = f"Athena finding: {finding.uuid}\n{marker.body_line}" if body is None else body
            if kind == "servicenow":
                display = marker.text if display is None else display
                correlation_id = str(finding.uuid) if correlation_id is None else correlation_id
        self.issues.append({
            "labels": list(labels or []), "correlation_id": correlation_id, "display": display, "idem": None,
            "key": ref, "event": None, "closed": closed, "project": project, "kind": kind, "body": body or "",
            "created": created or timezone.now(),
        })

    def post(self, url, *, headers, json):
        if url.endswith("/comment") or url.endswith("/comments"):
            self.comments.append((url, json.get("body")))
            return _Json(201, {"id": len(self.comments)})
        key = headers.get("Idempotency-Key")
        if key and any(i.get("idem") == key for i in self.issues):
            return _Json(200, {})
        self.creates += 1
        fields = json.get("fields") or {}
        labels = list(fields.get("labels") or json.get("labels") or [])
        if self.drop_labels and "/repos/" in url:
            labels = []
        n = len(self.issues) + 1
        kind = self._kind(url)
        ref = {"jira": f"SEC-{n}", "servicenow": f"sys{n}"}.get(kind, str(n))
        self.issues.append({
            "labels": labels, "correlation_id": json.get("correlation_id"), "display": json.get("correlation_display"),
            "idem": key, "key": ref, "event": json.get("event"), "closed": False,
            "project": (fields.get("project") or {}).get("key"), "kind": kind,
            "body": json.get("body") or fields.get("description") or json.get("description") or "",
            "created": timezone.now(),
        })
        if self.crash:
            self.crash = False
            raise Crash()
        return _Json(201, {
            "key": ref, "number": n, "result": {"sys_id": ref}, "code": 0,
            "labels": [{"name": label} for label in labels],
        })

    @staticmethod
    def _page(hits, params, size_key, page_key=None, offset_key=None):
        size = int(params.get(size_key, 50))
        start = int(params.get(offset_key, 0)) if offset_key else (int(params.get(page_key, 1)) - 1) * size
        return hits[start: start + size], start, size

    @staticmethod
    def _ordered(hits, oldest_first):
        """Oldest first when asked for; otherwise newest first, as these APIs order
        by default."""
        return sorted(hits, key=lambda i: i["created"], reverse=not oldest_first)

    def _jira(self, i, modern):
        created = i["created"].strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        description = (
            {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": i["body"]}]}]}
            if modern else i["body"]
        )
        return {"key": i["key"], "fields": {
            "status": {"statusCategory": {"key": "done" if i["closed"] else "new"}},
            "created": created, "description": description,
        }}

    def _github(self, i):
        return {"number": int(i["key"]), "state": "closed" if i["closed"] else "open",
                "created_at": i["created"].strftime("%Y-%m-%dT%H:%M:%SZ"), "body": i["body"]}

    def _servicenow(self, i):
        return {"sys_id": i["key"], "active": "false" if i["closed"] else "true",
                "sys_created_on": i["created"].strftime("%Y-%m-%d %H:%M:%S"),
                "correlation_display": i["display"] or "", "description": i["body"]}

    def get(self, url, *, headers, params=None):
        import re

        params = params or {}
        self.gets.append(url)
        if url.endswith("/rest/api/3/search/jql") or url.endswith("/rest/api/2/search"):
            modern = url.endswith("/search/jql")
            if modern and self.jira == "dc":
                return _Json(404, {"errorMessages": ["null for uri"]})
            if not modern and self.jira == "cloud":
                return _Json(410, {"errorMessages": ["The requested API has been removed. Migrate to /rest/api/3/search/jql."]})
            jql = params["jql"]
            project = jql.split('project = "')[1].split('"')[0] if 'project = "' in jql else None
            wanted = re.findall(r'"([^"]+)"', (re.search(r"labels in \(([^)]*)\)", jql) or [None, ""])[1])
            if 'labels = "' in jql:
                wanted.append(jql.split('labels = "')[1].split('"')[0])
            text = re.search(r'text ~ "\\"([^"\\]+)\\""', jql)
            hits = self._ordered([
                i for i in self.issues
                if i["kind"] == "jira" and (project is None or i["project"] == project)
                and (any(w in i["labels"] for w in wanted) or (text and text.group(1) in i["body"]))
            ], "ORDER BY created ASC" in jql)
            if modern:
                start = int(params.get("nextPageToken") or 0)
                size = int(params.get("maxResults", 50))
                page = hits[start: start + size]
                more = start + size < len(hits)
                body = {"issues": [self._jira(i, True) for i in page], "isLast": not more}
                if more:
                    body["nextPageToken"] = str(start + size)
                return _Json(200, body)
            page, _, _ = self._page(hits, params, "maxResults", offset_key="startAt")
            return _Json(200, {"issues": [self._jira(i, False) for i in page], "total": len(hits),
                               "startAt": int(params.get("startAt", 0))})
        match = re.search(r"/rest/api/2/issue/([^/]+)$", url)
        if match:
            issue = next((i for i in self.issues if i["kind"] == "jira" and i["key"] == match.group(1)), None)
            return _Json(404, {}) if issue is None else _Json(200, self._jira(issue, False))
        if url.endswith("/repos/acme/app/issues"):
            state = params.get("state", "open")
            hits = self._ordered([
                i for i in self.issues
                if i["kind"] == "github" and params["labels"] in i["labels"]
                and (state == "all" or (state == "closed") == i["closed"])
            ], params.get("sort") == "created" and params.get("direction") == "asc")
            page, _, _ = self._page(hits, params, "per_page", page_key="page")
            return _Json(200, [self._github(i) for i in page])
        match = re.search(r"/repos/acme/app/issues/(\d+)$", url)
        if match:
            issue = next((i for i in self.issues if i["kind"] == "github" and i["key"] == match.group(1)), None)
            return _Json(404, {}) if issue is None else _Json(200, self._github(issue))
        if url.endswith("/search/issues"):
            needle = params["q"].split('"')[1]
            hits = self._ordered(
                [i for i in self.issues if i["kind"] == "github" and needle in (i["body"] or "")],
                params.get("sort") == "created" and params.get("order") == "asc",
            )
            page, _, _ = self._page(hits, params, "per_page", page_key="page")
            return _Json(200, {"total_count": len(hits), "items": [self._github(i) for i in page]})
        match = re.search(r"/api/now/table/incident/([^/]+)$", url)
        if match:
            issue = next((i for i in self.issues if i["kind"] == "servicenow" and i["key"] == match.group(1)), None)
            return _Json(404, {}) if issue is None else _Json(200, {"result": self._servicenow(issue)})
        if "/api/now/table/" in url:
            wanted = dict(part.split("=", 1) for part in params["sysparm_query"].split("^") if "=" in part)
            hits = self._ordered([
                i for i in self.issues
                if i["kind"] == "servicenow" and all(i.get(k) == v for k, v in wanted.items())
            ], "ORDERBYsys_created_on" in params["sysparm_query"])
            page, _, _ = self._page(hits, params, "sysparm_limit", offset_key="sysparm_offset")
            return _Json(200, {"result": [self._servicenow(i) for i in page]})
        return _Json(404, {})

    def for_finding(self, finding):
        """The issues that carry ``finding`` in any form."""
        uuid = str(finding.uuid)
        return [
            i["key"] for i in self.issues
            if uuid in (i["body"] or "") or i["correlation_id"] == uuid or any(uuid in lab for lab in i["labels"])
            or (i["event"] or {}).get("uuid") == uuid
        ]

    def per_finding(self):
        import re

        counts = {}
        for i in self.issues:
            text = " ".join([*i["labels"], i["body"] or "", i["correlation_id"] or "", str((i["event"] or {}).get("uuid") or "")])
            found = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text)
            ident = found.group(0) if found else i["idem"]
            counts[ident] = counts.get(ident, 0) + 1
        return sorted(counts.values())


class _Calls(list):
    """Stands in for start_blocking_decision_dispatch: records each deployment."""

    def __init__(self):
        super().__init__()
        self.kwargs = []

    def __call__(self, deployment_id, **kwargs):
        self.append(deployment_id)
        self.kwargs.append(kwargs)
        return dispatch.STARTED


def _marker(dep):
    from assurance.connectors.base import finding_marker

    return finding_marker(Finding.objects.get(deployment=dep))


_ENDPOINTS = {
    "webhook": {"url": "https://hooks.example/athena"},
    "jira": {"base_url": "https://jira.example", "project_key": "SEC"},
    "github_issues": {"base_url": "https://api.github.example", "owner": "acme", "repo": "app"},
    "servicenow": {"base_url": "https://sn.example", "table": "incident"},
    "splunk": {"base_url": "https://splunk.example:8088", "index": "athena"},
}


def _ours(finding, connector="jira", ident=None, endpoint=None):
    """This installation's marker for ``finding`` as ``connector``'s adapter writes
    it, at the destination the tests bind (or ``endpoint``) -- under ``ident`` when
    given (another installation's)."""
    from assurance.connectors import build_connector
    from assurance.connectors.registry import get_connector_class

    config = get_connector_class(connector).config_from_binding(endpoint or _ENDPOINTS[connector], "tok")
    return build_connector(connector, config).marker(finding, ident)


def _lost(dep, connector="jira", *, outcome=DispatchAttempt.Outcome.UNKNOWN, carried=True, age=None, ref=""):
    """An uncertain attempt for ``dep``'s one finding, as a push whose answer was
    lost leaves it: ``carried`` -- recorded with the marker its push carried, as
    this release records it -- or not (NULL), as every release before recorded it.
    ``age`` in seconds since it was written."""
    from assurance.markers import MARKER_VERSION

    finding = Finding.objects.get(deployment=dep)
    attempt = DispatchAttempt.objects.create(
        deployment=dep, finding=finding, connector=connector, outcome=outcome,
        trigger=DispatchAttempt.Trigger.BLOCKING_DECISION, operation_id=dispatch.operation_id(finding, connector),
        policy_epoch=Deployment.Decision.PAUSED, external_ref=ref,
        marker=_ours(finding, connector).text if carried else None, marker_version=MARKER_VERSION if carried else None,
    )
    if age is not None:
        DispatchAttempt.objects.filter(pk=attempt.pk).update(updated_at=timezone.now() - timedelta(seconds=age))
    return attempt


def _installed_at():
    from assurance.markers import identity

    return identity().since


def _logged(caplog, text, timeout=5.0):
    """Whether ``text`` was logged -- waiting for it: what a stop's path logs is
    written by another thread (``oplog.log_later``), so no stop waits on a sink."""
    from assurance import oplog

    oplog.drain(timeout)
    return text in caplog.text


def _background():
    return [t for t in threading.enumerate() if t.name.startswith("assurance-dispatch-")]


def _settle(timeout=30.0):
    """Wait until no background dispatch is running in this process."""
    deadline = time.monotonic() + timeout
    while _background() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _background(), "a background dispatch was still running"


@pytest.fixture(autouse=True)
def _no_background_dispatch_outlives_its_test():
    yield
    _settle()


def _admin():
    return User.objects.create_user(username=f"a{User.objects.count()}", password="x", role=User.Roles.ADMIN)


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _findings(dep, count=2, severity="high"):
    """Open findings on ``dep``. Made BEFORE any policy exists, so the severity
    trigger has nothing to dispatch when they are saved."""
    for i in range(count):
        Finding.objects.create(
            deployment=dep, fingerprint=f"fp303-{dep.pk}-{i}", finding_type="prompt_injection",
            title=f"finding {i}", severity=severity, impact="i", recommendation="r", location="/x",
        )


def _opted_in(dep, connector="jira", min_severity="high"):
    """A binding with a credential and a policy opting into the decision trigger."""
    endpoint = _ENDPOINTS[connector]
    binding = ConnectorBinding(deployment=dep, connector=connector, enabled=True, endpoint=endpoint)
    binding.set_secret("jira-tok")
    binding.save()
    DispatchPolicy.objects.create(
        deployment=dep, enabled=True, min_severity=min_severity, on_blocking_decision=True
    )


def _scanned(owner):
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=owner)
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    return Deployment.objects.get(pk=dep.pk)


def _warm(client, dep):
    """The first request of a process imports the URLconf: pay it before timing."""
    client.get(f"/api/assurance/deployments/{dep.uuid}/dispatch-attempts/")


def _timed(call, connector):
    began = time.monotonic()
    response = call()
    return response, time.monotonic() - began, connector.finished


def _wait_for(predicate, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _sent(dep):
    return DispatchAttempt.objects.filter(
        deployment=dep, outcome=DispatchAttempt.Outcome.SENT, trigger=DispatchAttempt.Trigger.BLOCKING_DECISION
    ).count()


# --------------------------------------------------------------------- measured


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_pause_answers_before_a_slow_dispatch_and_the_dispatch_still_happens(monkeypatch):
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"),
        connector,
    )
    connector.release.set()

    assert response.status_code == 200, response.content
    assert response.json()["decision"] == Deployment.Decision.PAUSED
    assert took < PROMPT, f"the pause answered after {took:.3f}s: it waited on the dispatch"
    assert finished == 0, "a push finished before the pause answered"
    # Committed before it answered: a reader sees the pause at once -- and the
    # dispatch it owes, committed with it, before any push has finished.
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
    assert DecisionDispatchDue.objects.filter(deployment=dep).exists()
    # And the dispatch still happens, after.
    assert _wait_for(lambda: _sent(dep) == 2), list(DispatchAttempt.objects.values_list("outcome", "detail"))
    _settle()
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_lift_that_lands_on_a_blocking_decision_answers_before_a_slow_dispatch(monkeypatch):
    """The policy opts in while the deployment is paused; the lift lands on
    NEEDS_REMEDIATION, which is blocking, so it is the lift that dispatches."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    client = _client(admin)
    _warm(client, dep)
    assert client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json").status_code == 200
    _settle()
    _opted_in(dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json"),
        connector,
    )
    connector.release.set()

    assert response.status_code == 200, response.content
    assert response.json()["decision"] == Deployment.Decision.NEEDS_REMEDIATION
    assert took < PROMPT, f"the lift answered after {took:.3f}s: it waited on the dispatch"
    assert finished == 0
    assert _wait_for(lambda: _sent(dep) == 2)


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_recompute_that_keeps_a_pause_answers_before_a_slow_dispatch(monkeypatch):
    """A recompute with no ``paused`` keeps the pause the row holds, and the
    decision it keeps is blocking."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    client = _client(admin)
    _warm(client, dep)
    client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    _settle()
    _opted_in(dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json"), connector
    )
    connector.release.set()

    assert response.json()["decision"] == Deployment.Decision.PAUSED
    assert took < PROMPT, f"the recompute answered after {took:.3f}s"
    assert finished == 0
    assert _wait_for(lambda: _sent(dep) == 2)


def _with_claims(owner):
    dep = Deployment.objects.create(name=f"c{Deployment.objects.count()}", owner=owner)
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False, third_party_sharing_allowed=False
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
        classification=Asset.Classification.KNOWN,
    )
    derive_claims(Deployment.objects.get(pk=dep.pk))
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    return Deployment.objects.get(pk=dep.pk)


@with_key
@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("to_status", [AssuranceClaim.ClaimStatus.REVOKED, AssuranceClaim.ClaimStatus.CONTRADICTED])
def test_a_revoke_or_a_contradiction_answers_promptly_beside_a_slow_connector(monkeypatch, to_status):
    """Neither schedules the dispatch; this holds that, with a connector that
    would hold the answer for seconds if either ever did."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _with_claims(admin)
    _findings(dep)
    _opted_in(dep)
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    client = _client(admin)
    _warm(client, dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": to_status}, format="json"),
        connector,
    )
    connector.release.set()

    assert response.status_code == 200, response.content
    assert took < PROMPT, f"the {to_status} answered after {took:.3f}s"
    assert finished == 0 and connector.started == 0


# ------------------------------------------------ after the answer: never lost


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_pause_whose_dispatch_fails_answers_and_the_failure_stays_owed(monkeypatch, caplog):
    connector = HeldConnector(status=503)
    connector.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    monkeypatch.setattr(dispatch, "RETRY_DELAYS", (0.05,))
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
        assert response.status_code == 200
        _settle()

    owed = DecisionDispatchDue.objects.get(deployment=dep)
    # The first run and its one retry, each pushing and failing.
    assert owed.runs == 2 and connector.finished == 2
    assert "jira" in owed.last_error and "503" in owed.last_error
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.FAILED
    assert "still owed after 2 run(s)" in caplog.text
    # And it is shown to anyone who reads the deployment's dispatch record.
    shown = client.get(f"/api/assurance/deployments/{dep.uuid}/dispatch-attempts/").json()
    assert shown["blocking_decision_dispatch_owed"]["runs"] == 2
    assert "503" in shown["blocking_decision_dispatch_owed"]["last_error"]


@with_key
def test_a_run_records_what_it_owes_before_it_pushes_and_settles_only_when_nothing_failed(monkeypatch):
    """Paused without the route, so no stop recorded it: the run writes the row
    itself before its first push."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    seen_at_push = []

    class Recording(HeldConnector):
        def post(self, url, *, headers, json):
            # A process killed here must leave the dispatch recorded as owed.
            seen_at_push.append(DecisionDispatchDue.objects.filter(deployment=dep).exists())
            return _Answer(self.status)

    failing = Recording(status=500)
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=failing.factory) == dispatch.OWED
    assert seen_at_push == [True]
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert owed.runs == 1 and "500" in owed.last_error

    def raising(deployment, *, transport_factory=None, before_push=None):
        raise RuntimeError("the connector table is locked")

    monkeypatch.setattr(dispatch, "dispatch_for_blocking_decision", raising)
    assert dispatch.run_blocking_decision_dispatch(dep.pk) == dispatch.OWED
    owed.refresh_from_db()
    assert owed.runs == 2 and "RuntimeError: the connector table is locked" in owed.last_error
    monkeypatch.undo()

    working = Recording(status=201)
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=working.factory) == {dep.pk: dispatch.SETTLED}
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.SENT


@with_key
def test_nothing_is_owed_once_the_decision_that_asked_for_it_no_longer_holds():
    """An owed dispatch retried after the pause was lifted to a decision that is
    not blocking pushes nothing -- it would be executing a withdrawn decision --
    and is no longer owed."""
    admin = _admin()
    dep = _scanned(admin)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now(), runs=3, last_error="503")
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False)
    assert Deployment.objects.get(pk=dep.pk).decision not in dispatch._BLOCKING_DECISIONS
    connector = HeldConnector()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert connector.started == 0
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_the_retry_command_runs_what_is_owed_and_fails_while_anything_still_is(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now())
    failing = HeldConnector(status=503)
    failing.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", failing.factory)
    try:
        call_command("retry_blocking_dispatches")
    except CommandError as exc:
        assert str(dep.pk) in str(exc), exc
    else:
        raise AssertionError("the command reported nothing owed while a dispatch still was")
    assert DecisionDispatchDue.objects.get(deployment=dep).runs == 1

    working = HeldConnector()
    working.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", working.factory)
    call_command("retry_blocking_dispatches")
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert working.finished == 1


# ----------------------------------------------------------- how it is started


@with_key
def test_the_route_only_schedules_the_dispatch_for_after_its_commit(django_capture_on_commit_callbacks, monkeypatch):
    """Inside a transaction nothing starts: one hook, for this deployment, and no
    thread until the transaction commits."""
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    dep = _scanned(admin)
    _opted_in(dep)
    with django_capture_on_commit_callbacks(execute=False) as callbacks:
        response = _client(admin).post(
            f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
        )
    assert response.status_code == 200
    hooks = [c for c in callbacks if isinstance(c, dispatch._BlockingDispatchAfterCommit)]
    assert [h.deployment_id for h in hooks] == [dep.pk]
    assert started == []
    hooks[0]()
    assert started == [dep.pk]


def test_a_flood_of_stops_runs_one_background_dispatch_per_deployment(monkeypatch):
    """While one run is held, twenty more stops of the same deployment start no
    thread: the one running runs once more for all of them, and then is done."""
    held, runs = threading.Event(), []

    def run(deployment_id, *, transport_factory=None, token=None):
        runs.append(deployment_id)
        held.wait(HOLD)
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    dispatch.start_blocking_decision_dispatch(4242)
    assert _wait_for(lambda: runs == [4242], timeout=5)
    for _ in range(20):
        dispatch.start_blocking_decision_dispatch(4242)
    assert [t.name for t in _background()] == ["assurance-dispatch-4242"]
    held.set()
    _settle()
    assert runs == [4242, 4242]
    assert 4242 not in dispatch._JOBS


def test_a_run_that_raises_is_retried_in_the_background(monkeypatch):
    runs = []

    def run(deployment_id, *, transport_factory=None, token=None):
        runs.append(deployment_id)
        if len(runs) == 1:
            raise RuntimeError("database is locked")
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    monkeypatch.setattr(dispatch, "RETRY_DELAYS", (0.01, 0.01))
    dispatch.start_blocking_decision_dispatch(4343)
    _settle()
    assert runs == [4343, 4343]
    assert 4343 not in dispatch._JOBS


@with_key
def test_a_background_dispatch_that_cannot_start_does_not_fail_the_stop(
    django_capture_on_commit_callbacks, monkeypatch, caplog
):
    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    admin = _admin()
    dep = _scanned(admin)
    _opted_in(dep)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        with django_capture_on_commit_callbacks(execute=True):
            response = _client(admin).post(
                f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
            )
        assert response.status_code == 200
        assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
        monkeypatch.undo()
        assert _logged(caplog, f"retry_blocking_dispatches --deployment {dep.pk}")
    # Nothing is left claiming a run is in progress.
    assert dep.pk not in dispatch._JOBS


# ------------------------------------------- owed from the moment the stop commits


def _paused_via_route(client, dep):
    return client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_process_that_exits_right_after_the_stop_leaves_the_dispatch_owed(monkeypatch):
    """The worker answers the pause and exits before its background thread has
    written anything -- a graceful restart, a recycled worker. The dispatch was
    recorded in the pause's own transaction, so the next process finds it owed
    and the retry command runs it."""
    connector = HeldConnector()
    connector.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    exited_with = _Calls()
    # The process is gone before the thread runs: it never starts.
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", exited_with)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    response = _paused_via_route(client, dep)

    assert response.status_code == 200 and response.json()["decision"] == Deployment.Decision.PAUSED
    assert exited_with == [dep.pk] and connector.started == 0
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert owed.requests == 1 and owed.runs == 0 and owed.run_token == ""
    monkeypatch.undo()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    call_command("retry_blocking_dispatches")
    assert _sent(dep) == 2
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_the_owed_record_commits_with_the_stop_or_not_at_all():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    _opted_in(dep)
    with pytest.raises(RuntimeError), transaction.atomic():
        recompute_decision(
            Deployment.objects.get(pk=dep.pk), paused=True,
            also_in_transaction=dispatch.record_blocking_dispatch_owed,
        )
        assert DecisionDispatchDue.objects.filter(deployment=dep).exists()
        raise RuntimeError("the stop's transaction rolls back")
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert Deployment.objects.get(pk=dep.pk).decision != Deployment.Decision.PAUSED
    # Each stop that asks counts; a decision that owes nothing records nothing.
    for _ in range(2):
        recompute_decision(
            Deployment.objects.get(pk=dep.pk), paused=True,
            also_in_transaction=dispatch.record_blocking_dispatch_owed,
        )
    assert DecisionDispatchDue.objects.get(deployment=dep).requests == 2
    DispatchPolicy.objects.filter(deployment=dep).update(on_blocking_decision=False)
    other = _scanned(admin)
    recompute_decision(other, paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed)
    assert not DecisionDispatchDue.objects.filter(deployment=other).exists()


@with_key
def test_a_stop_whose_owed_record_cannot_be_written_still_stops_and_the_run_writes_it(
    django_capture_on_commit_callbacks, monkeypatch, caplog
):
    """The savepoint fails; the stop neither fails nor waits, and the pause stands.
    The background run then records the dispatch itself before its first push."""
    def broken(**kwargs):
        raise DatabaseError("disk I/O error")

    monkeypatch.setattr(DecisionDispatchDue.objects, "create", broken)
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        began = time.monotonic()
        with django_capture_on_commit_callbacks(execute=True):
            response = _paused_via_route(client, dep)
        took = time.monotonic() - began
    assert response.status_code == 200 and response.json()["decision"] == Deployment.Decision.PAUSED
    assert took < PROMPT
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
    assert _logged(caplog, "could not record the blocking-decision dispatch")
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert started == [dep.pk]
    monkeypatch.undo()

    seen_at_push = []

    class Recording(HeldConnector):
        def post(self, url, *, headers, json):
            seen_at_push.append(DecisionDispatchDue.objects.filter(deployment=dep).exists())
            return _Answer(503)

    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=Recording().factory) == dispatch.OWED
    assert seen_at_push == [True]
    assert DecisionDispatchDue.objects.get(deployment=dep).runs == 1


# --------------------------------------------------- the last word is a true one


@with_key
def test_the_last_log_says_it_stays_recorded_only_when_it_does(monkeypatch, caplog):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    monkeypatch.setattr(dispatch, "RETRY_DELAYS", (0.0, 0.0))

    def locked(deployment, token):
        raise OperationalError("database is locked")

    # 1. Recorded by the stop; every run then fails before it can claim it.
    monkeypatch.setattr(dispatch, "_claim", locked)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        dispatch._run_until_settled(dep.pk, "t1")
    assert "is still owed after 3 run(s); it stays recorded" in caplog.text
    assert DecisionDispatchDue.objects.filter(deployment=dep).exists()
    caplog.clear()

    # 2. Not recorded, and the run cannot write it either: the log says so, and
    #    names the command that runs it -- it never claims a record that is not there.
    DecisionDispatchDue.objects.filter(deployment=dep).delete()

    def cannot(*args, **kwargs):
        raise OperationalError("database is locked")

    monkeypatch.setattr(DecisionDispatchDue.objects, "get_or_create", cannot)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        dispatch._run_until_settled(dep.pk, "t2")
    assert "stays recorded" not in caplog.text
    assert (
        f"is still owed after 3 run(s), and no record of it could be written: run "
        f"`manage.py retry_blocking_dispatches --deployment {dep.pk}`"
    ) in caplog.text
    caplog.clear()

    # 3. Whether it is recorded cannot even be read.
    def unreadable(deployment_id):
        raise OperationalError("database is locked")

    monkeypatch.setattr(dispatch, "_owed_row", unreadable)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        dispatch._run_until_settled(dep.pk, "t3")
    assert "stays recorded" not in caplog.text
    assert "whether it is recorded could not be read" in caplog.text
    assert f"--deployment {dep.pk}" in caplog.text


# ------------------------------------------------- one runner at a time, anywhere


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_scheduled_retry_during_a_background_run_pushes_nothing_twice(monkeypatch):
    """The cron fires while the background thread is mid-push -- the hung-
    connector case this exists for. It finds the dispatch claimed, pushes nothing,
    and says so; a second process's thread for a second pause does the same. Each
    finding is pushed exactly once."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    assert _paused_via_route(client, dep).status_code == 200
    assert _wait_for(lambda: connector.started == 1, timeout=5)
    # The scheduled command, here and now.
    assert dispatch.retry_owed_blocking_dispatches() == {dep.pk: dispatch.ELSEWHERE}
    out = io.StringIO()
    with pytest.raises(CommandError, match=rf"\[{dep.pk}\]"):
        call_command("retry_blocking_dispatches", stdout=out)
    assert f"deployment {dep.pk}: running elsewhere" in out.getvalue()
    assert "ran 0 blocking-decision dispatch(es), 1 running elsewhere" in out.getvalue()
    # Another worker process pauses it again: its own thread, knowing nothing of this one's.
    dispatch._JOBS.clear()
    assert _paused_via_route(client, dep).status_code == 200
    assert connector.started == 1
    connector.release.set()
    _settle()

    assert sorted(connector.bodies.count(b) for b in set(connector.bodies)) == [1, 1, 1]
    assert connector.started == 3
    assert list(DispatchAttempt.objects.filter(deployment=dep).values_list("outcome", "attempts")) == [
        (DispatchAttempt.Outcome.SENT, 1)
    ] * 3
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_a_claim_is_skipped_while_live_and_taken_back_once_it_lapses():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    connector = HeldConnector()
    connector.release.set()
    live = timezone.now() + timedelta(seconds=60)
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=live, run_token="other-runner")

    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.ELSEWHERE
    assert connector.started == 0
    # The runner holding it may run again under its own claim.
    assert (
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory, token="other-runner")
        == dispatch.SETTLED
    )
    assert connector.started == 1

    # A runner that died leaves a claim that lapses; the next one takes it back.
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    DispatchAttempt.objects.filter(deployment=dep).delete()
    lapsed = timezone.now() - timedelta(seconds=1)
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=lapsed, run_token="dead-runner")
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert connector.started == 2


@with_key
def test_a_run_that_loses_its_claim_pushes_nothing_more(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )

    class TakenOver(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            # Another runner takes the row after this runner's claim was judged dead.
            DecisionDispatchDue.objects.filter(deployment=dep).update(run_token="someone-else")
            return _Answer(201)

    connector = TakenOver()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.ELSEWHERE
    assert connector.started == 1
    assert DecisionDispatchDue.objects.get(deployment=dep).run_token == "someone-else"


@with_key
def test_a_webhook_push_carries_the_operation_id_as_its_idempotency_key():
    """A second push of one operation -- across processes, say -- is one to a
    receiver that deduplicates on it. Jira has no such header, so none is sent."""
    admin = _admin()
    for connector_name in ("webhook", "jira"):
        dep = _scanned(admin)
        _findings(dep, count=1)
        _opted_in(dep, connector=connector_name)
        recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
        connector = HeldConnector()
        connector.release.set()
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
        attempt = DispatchAttempt.objects.get(deployment=dep)
        finding = Finding.objects.get(deployment=dep)
        assert attempt.operation_id == dispatch.operation_id(finding, connector_name)
        if connector_name == "webhook":
            assert connector.headers[0]["Idempotency-Key"] == attempt.operation_id
        else:
            assert "Idempotency-Key" not in connector.headers[0]


# ------------------------------------------------------- the global kill switch


@with_key
def test_the_kill_switch_never_drops_what_is_owed(monkeypatch, django_capture_on_commit_callbacks):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=2)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    failing = HeldConnector(status=503)
    failing.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=failing.factory) == dispatch.OWED
    working = HeldConnector()
    working.release.set()

    with override_settings(ASSURANCE_AUTO_DISPATCH_ENABLED=False):
        # Switched off: the scheduled retry pushes nothing and drops nothing.
        assert dispatch.retry_owed_blocking_dispatches(transport_factory=working.factory) == {
            dep.pk: dispatch.DISABLED
        }
        out = io.StringIO()
        with pytest.raises(CommandError, match=rf"\[{dep.pk}\]"):
            call_command("retry_blocking_dispatches", stdout=out)
        assert "ran 0 blocking-decision dispatch(es), 0 running elsewhere, 1 held while auto-dispatch" in out.getvalue()
        assert DecisionDispatchDue.objects.get(deployment=dep).runs == 1
        # And a stop records nothing new and schedules nothing.
        other = _scanned(admin)
        _findings(other, count=1)
        _opted_in(other)
        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            assert _paused_via_route(_client(admin), other).status_code == 200
        assert not [c for c in callbacks if isinstance(c, dispatch._BlockingDispatchAfterCommit)]
        assert not DecisionDispatchDue.objects.filter(deployment=other).exists()
    assert working.started == 0

    # Switched back on, the retry runs what was kept.
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=working.factory) == {dep.pk: dispatch.SETTLED}
    assert working.started == 2 and _sent(dep) == 2


@with_key
def test_a_run_halts_and_keeps_the_row_when_the_switch_goes_off_mid_run():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    switched_off = override_settings(ASSURANCE_AUTO_DISPATCH_ENABLED=False)

    class SwitchedOff(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if self.started == 1:
                switched_off.enable()
            return _Answer(201)

    connector = SwitchedOff()
    try:
        outcome = dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory)
    finally:
        switched_off.disable()
    assert outcome == dispatch.DISABLED
    assert connector.started == 1
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert owed.run_token == "" and owed.running_until is None
    # Held, not failed: switching off is no run that went wrong.
    assert (owed.runs, owed.last_error) == (0, "")


# ------------------------------------------- the decision is checked every push


@with_key
def test_a_run_stops_pushing_once_the_pause_that_asked_for_it_is_lifted():
    """The lift lands on a decision that does not block. The run checks before
    every push, so the pushes after the lift are never made -- not one of them
    under the withdrawn pause -- and nothing is owed any more."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3, severity="low")
    _opted_in(dep, min_severity="low")
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    lifted = []

    class LiftedMidRun(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if not lifted:
                lifted.append(recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False))
            return _Answer(201)

    connector = LiftedMidRun()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert lifted and lifted[0] not in dispatch._BLOCKING_DECISIONS, lifted
    assert connector.started == 1
    assert list(DispatchAttempt.objects.filter(deployment=dep).values_list("outcome", "policy_epoch")) == [
        (DispatchAttempt.Outcome.SENT, Deployment.Decision.PAUSED)
    ]
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_a_stop_that_asks_again_mid_run_is_run_for_before_the_row_is_settled(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=2)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    passes = []
    real = dispatch._run_claimed

    def counted(claim, asked, transport_factory):
        passes.append(asked)
        return real(claim, asked, transport_factory)

    monkeypatch.setattr(dispatch, "_run_claimed", counted)

    class AskedAgain(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if self.started == 1:
                recompute_decision(
                    Deployment.objects.get(pk=dep.pk), paused=True,
                    also_in_transaction=dispatch.record_blocking_dispatch_owed,
                )
            return _Answer(201)

    connector = AskedAgain()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert passes == [1, 2]
    assert connector.started == 2 and _sent(dep) == 2
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_a_check_that_cannot_be_made_halts_the_run_and_keeps_it_owed(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=2)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    real = dispatch._owed_row
    calls = []

    def flaky(deployment_id):
        calls.append(1)
        # The run's read of what is asked, its claim, the check before the first
        # push -- and then the check before the second push fails.
        if len(calls) == 4:
            raise OperationalError("database is locked")
        return real(deployment_id)

    monkeypatch.setattr(dispatch, "_owed_row", flaky)
    connector = HeldConnector()
    connector.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.OWED
    assert connector.started == 1
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert "the check before a push raised OperationalError" in owed.last_error and owed.run_token == ""


# ------------------------------------------------------------ what is not retried


@with_key
def test_a_push_whose_answer_was_lost_stays_owed_until_it_is_looked_for(monkeypatch):
    """A push whose answer was lost may have created the ticket. It is never sent
    again blind, and it does not settle the dispatch: it stays owed until a look
    at the system settles it -- found (no second push) or absent (pushed once)."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )

    class AnswerLost(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            raise TimeoutError("read timed out")

    lost = AnswerLost()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=lost.factory) == dispatch.OWED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN
    assert "unknown" in DecisionDispatchDue.objects.get(deployment=dep).last_error
    # A transport that cannot look: held, still owed, nothing sent again.
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=lost.factory) == {dep.pk: dispatch.OWED}
    assert lost.started == 1

    # One that can, and the system has it: recorded SENT with its key, not sent again.
    remote = FakeRemote()
    remote.add("SEC-77", Finding.objects.get(deployment=dep))
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=remote.factory) == {dep.pk: dispatch.SETTLED}
    attempt.refresh_from_db()
    assert (attempt.outcome, attempt.external_ref, remote.creates) == (DispatchAttempt.Outcome.SENT, "SEC-77", 0)
    assert attempt.reconciled_at is not None


@with_key
def test_a_lost_answer_the_system_never_received_is_pushed_once_after_the_look(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    _lost(dep)
    remote = FakeRemote()
    # Absent, but so recently sent that the request may still be on its way: held.
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    assert remote.creates == 0
    # Absent, long enough after: certainly not there, so pushed -- once.
    DispatchAttempt.objects.filter(deployment=dep).update(
        updated_at=timezone.now() - timedelta(seconds=dispatch.CLAIM_SECONDS + 1)
    )
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.SENT


# ------------------------------------------------------------- the retry command


@with_key
def test_the_retry_command_with_deployment_runs_and_reports_only_those(monkeypatch):
    admin = _admin()
    a, b = _scanned(admin), _scanned(admin)
    for dep in (a, b):
        _findings(dep, count=1)
        _opted_in(dep)
        recompute_decision(
            Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
        )
    down = HeldConnector(status=503)
    down.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", down.factory)
    assert dispatch.run_blocking_decision_dispatch(a.pk) == dispatch.OWED
    working = HeldConnector()
    working.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", working.factory)

    out = io.StringIO()
    call_command("retry_blocking_dispatches", "--deployment", str(b.pk), stdout=out)
    assert f"for 1 of deployment(s) [{b.pk}] only" in out.getvalue()
    assert "no other deployment was checked" in out.getvalue()
    assert working.started == 1  # B's, and not A's
    assert not DecisionDispatchDue.objects.filter(deployment=b).exists()
    assert DecisionDispatchDue.objects.get(deployment=a).runs == 1

    monkeypatch.setattr(dispatch, "_default_transport_factory", down.factory)
    with pytest.raises(CommandError, match=rf"\[{a.pk}\]"):
        call_command("retry_blocking_dispatches", "--deployment", str(a.pk), stdout=io.StringIO())
    # Without it: non-zero while anything at all is owed.
    with pytest.raises(CommandError, match=rf"\[{a.pk}\]"):
        call_command("retry_blocking_dispatches", stdout=io.StringIO())


@with_key
def test_one_deployment_whose_retry_raises_does_not_stop_the_rest(monkeypatch):
    admin = _admin()
    a, b = _scanned(admin), _scanned(admin)
    now = timezone.now()
    DecisionDispatchDue.objects.create(deployment=a, owed_since=now - timedelta(seconds=5))
    DecisionDispatchDue.objects.create(deployment=b, owed_since=now)
    real = dispatch.run_blocking_decision_dispatch

    def run(deployment_id, **kwargs):
        if deployment_id == a.pk:
            raise OperationalError("database is locked")
        return real(deployment_id, **kwargs)

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    assert dispatch.retry_owed_blocking_dispatches() == {a.pk: dispatch.OWED, b.pk: dispatch.SETTLED}


# ---------------------------------------------------------------- the thread itself


def test_the_background_thread_is_a_daemon_and_the_stop_has_recorded_what_it_owes(monkeypatch):
    """A daemon never holds a worker's exit -- and need not, because the row was
    committed with the stop before any thread exists."""
    made = []

    class Recorded:
        def __init__(self, *args, **kwargs):
            made.append(kwargs)

        def start(self):
            pass

    monkeypatch.setattr(dispatch.threading, "Thread", Recorded)
    dispatch.start_blocking_decision_dispatch(4545)
    dispatch._JOBS.pop(4545, None)
    assert made and made[0]["daemon"] is True
    assert made[0]["name"] == "assurance-dispatch-4545"


def test_the_background_thread_closes_its_own_connections(monkeypatch):
    used = []

    def run(deployment_id, *, transport_factory=None, token=None):
        Deployment.objects.exists()
        used.append(connections["default"])
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    dispatch.start_blocking_decision_dispatch(4646)
    _settle()
    assert used and used[0].connection is None, "the thread left its connection open"


def test_the_owed_dispatch_is_read_only_in_the_admin():
    model_admin = django_admin.site._registry[DecisionDispatchDue]
    request = RequestFactory().get("/admin/")
    request.user = User.objects.create_superuser(username="su", password="x", email="su@example.com")
    assert model_admin.has_add_permission(request) is False
    assert model_admin.has_change_permission(request) is False
    assert {"requests", "running_until", "run_token"} <= set(model_admin.readonly_fields)


@with_key
def test_a_long_run_renews_its_claim_before_it_can_lapse(monkeypatch):
    """Four pushes of forty seconds each outlast one claim. Renewed before each push
    that needs it, the claim never lapses under a live run -- a lapsed one would let
    a second runner push the same findings."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=4)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    real_now = timezone.now
    skew = [timedelta(0)]

    class Clock:
        @staticmethod
        def now():
            return real_now() + skew[0]

    monkeypatch.setattr(dispatch, "timezone", Clock)
    left = []

    class Slow(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            until = DecisionDispatchDue.objects.get(deployment=dep).running_until
            left.append((until - Clock.now()).total_seconds())
            skew[0] += timedelta(seconds=40)
            return _Answer(201)

    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=Slow().factory) == dispatch.SETTLED
    assert len(left) == 4
    assert min(left) > dispatch.CLAIM_SECONDS - dispatch.CLAIM_RENEW_AFTER - 1, left


def test_a_flood_across_deployments_runs_a_bounded_number_at_once(monkeypatch):
    """Stops of many deployments start a thread each, but only a few push at once:
    the rest wait asleep, so a flood does not crowd out the process's requests."""
    held, lock, running, peak = threading.Event(), threading.Lock(), [0], [0]

    def run(deployment_id, *, transport_factory=None, token=None):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        held.wait(0.3)
        with lock:
            running[0] -= 1
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    for pk in range(5000, 5012):
        dispatch.start_blocking_decision_dispatch(pk)
    assert len(_background()) == 12
    _settle()
    assert peak[0] == dispatch.DEFAULT_MAX_CONCURRENT_RUNS == 4


@with_key
def test_a_run_whose_decision_moves_to_another_blocking_one_records_the_one_in_force():
    """Lifted mid-run onto NEEDS_REMEDIATION -- still blocking, so the run goes on
    -- and every push after the lift records the authority it was made under."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    lifted = []

    class LiftedMidRun(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if not lifted:
                lifted.append(recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False))
            return _Answer(201)

    connector = LiftedMidRun()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert lifted == [Deployment.Decision.NEEDS_REMEDIATION]
    assert connector.started == 3
    assert list(
        DispatchAttempt.objects.filter(deployment=dep).order_by("finding_id").values_list("policy_epoch", flat=True)
    ) == [Deployment.Decision.PAUSED, Deployment.Decision.NEEDS_REMEDIATION, Deployment.Decision.NEEDS_REMEDIATION]


@with_key
def test_the_retry_command_fails_for_a_dispatch_a_stop_owes_while_it_runs(monkeypatch):
    """A stop lands while the scheduled command is running; what it owes was not in
    the command's list, and the command still does not report nothing owed."""
    admin = _admin()
    a, b = _scanned(admin), _scanned(admin)
    for dep in (a, b):
        _findings(dep, count=1)
        _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=a.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )

    class PausedMeanwhile(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            recompute_decision(
                Deployment.objects.get(pk=b.pk), paused=True,
                also_in_transaction=dispatch.record_blocking_dispatch_owed,
            )
            return _Answer(201)

    monkeypatch.setattr(dispatch, "_default_transport_factory", PausedMeanwhile().factory)
    with pytest.raises(CommandError, match=rf"\[{b.pk}\]"):
        call_command("retry_blocking_dispatches", stdout=io.StringIO())
    assert not DecisionDispatchDue.objects.filter(deployment=a).exists()


def test_a_deployment_that_does_not_exist_is_reported_and_fails_the_command():
    out = io.StringIO()
    with pytest.raises(CommandError, match=r"987654 no such deployment"):
        call_command("retry_blocking_dispatches", "--deployment", "987654", stdout=out)
    assert "deployment 987654: no such deployment" in out.getvalue()


# ============================================================ round 2

# ------------------------------------------ the record can never undo the stop


def _ends_the_transaction(**kwargs):
    """What SQLite does on some I/O, full-disk, memory and busy errors inside a
    transaction: it rolls the WHOLE transaction back, then the statement fails."""
    from django.db import connection

    connection.connection.execute("ROLLBACK")
    raise OperationalError("disk I/O error")


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_record_that_ends_the_stops_transaction_does_not_undo_the_stop(monkeypatch, caplog):
    """The owed record fails in a way that ends the stop's transaction. The stop is
    committed anyway -- again, without the record -- and the answer is the stored
    decision. It used to answer 200 "paused" over a decision that stayed as it was."""
    monkeypatch.setattr(DecisionDispatchDue.objects, "create", _ends_the_transaction)
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)
    before = Deployment.objects.get(pk=dep.pk).decision
    assert before != Deployment.Decision.PAUSED

    with caplog.at_level(logging.ERROR):
        response, took, _ = _timed(lambda: _paused_via_route(client, dep), HeldConnector())
        assert _logged(caplog, "the stop is committed again without the record")

    assert response.status_code == 200, response.content
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
    assert response.json() == {"decision": "paused", "decision_label": "Deployment paused"}
    assert took < PROMPT
    # Not recorded, so the background run is started to record and run it.
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert started == [dep.pk]
    monkeypatch.undo()
    connector = HeldConnector()
    connector.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert _sent(dep) == 1


@with_key
def test_a_hook_that_raises_commits_nothing():
    admin = _admin()
    dep = _scanned(admin)
    before = Deployment.objects.get(pk=dep.pk).decision

    def raises(locked, decision):
        raise RuntimeError("the hook broke")

    from assurance.decision import TransactionLostInHook

    with pytest.raises(TransactionLostInHook):
        recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=raises)
    assert Deployment.objects.get(pk=dep.pk).decision == before


@with_key
def test_the_route_answers_the_stored_decision(monkeypatch):
    """Whatever the recompute computed, the answer is what was committed."""
    from assurance import decision as decision_module

    admin = _admin()
    dep = _scanned(admin)
    real = decision_module.recompute_decision

    def computes_paused_but_stores_nothing(deployment, **kwargs):
        real(deployment, **{k: v for k, v in kwargs.items() if k != "paused"})
        return Deployment.Decision.PAUSED

    monkeypatch.setattr("assurance.views.recompute_decision", computes_paused_but_stores_nothing)
    response = _paused_via_route(_client(admin), dep)
    stored = Deployment.objects.get(pk=dep.pk).decision
    assert stored != Deployment.Decision.PAUSED
    assert response.json()["decision"] == stored


# ---------------------------------------- never twice: in flight, lapsed, crashed


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "github_issues", "servicenow", "webhook"])
def test_a_runner_that_dies_mid_push_leaves_exactly_one_issue_per_finding(connector_name):
    """The runner dies right after the system committed the create, before the
    answer is back: the attempt is left SENDING. The next runner (its claim lapsed)
    finds the issue -- or, for the webhook, resends under the same key, which the
    receiver drops -- and pushes the rest. One issue per finding, whatever happened."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep, connector=connector_name)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    remote = FakeRemote()
    remote.crash = True
    with pytest.raises(Crash):
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory, token="dead")
    assert list(DispatchAttempt.objects.filter(deployment=dep).values_list("outcome", flat=True)) == [
        DispatchAttempt.Outcome.SENDING
    ]
    # The dead runner's claim lapses; the next runner takes the dispatch over.
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=timezone.now() - timedelta(seconds=1))
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.per_finding() == [1, 1, 1]
    attempts = DispatchAttempt.objects.filter(deployment=dep)
    assert {a.outcome for a in attempts} == {DispatchAttempt.Outcome.SENT}
    if connector_name != "webhook":
        # The issue each finding became is recorded the moment it is known.
        assert all(a.external_ref for a in attempts), [(a.finding_id, a.external_ref) for a in attempts]


@with_key
def test_a_splunk_push_whose_end_is_unknown_is_held_until_a_person_reconciles_it():
    """Splunk HEC has no read-back, and a second event is a second event: the push
    is never resent blind, the dispatch stays owed, and the reconcile command
    settles it. Every event carries the finding's uuid."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep, connector="splunk")
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    remote.crash = True
    with pytest.raises(Crash):
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory, token="dead")
    assert remote.issues[0]["event"]["uuid"] == str(finding.uuid)
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=timezone.now() - timedelta(seconds=1))
    DispatchAttempt.objects.filter(deployment=dep).update(
        updated_at=timezone.now() - timedelta(seconds=dispatch.CLAIM_SECONDS + 1)
    )
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    assert remote.creates == 1
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert attempt.outcome == DispatchAttempt.Outcome.SENDING
    out = io.StringIO()
    call_command("reconcile_dispatch_attempt", str(attempt.uuid), "--provider-has-it", "--by", "ops", stdout=out)
    assert "is now sent" in out.getvalue()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1


@with_key
def test_a_push_is_recorded_as_sending_before_the_request_goes_out():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    seen = []

    class Watching(HeldConnector):
        def post(self, url, *, headers, json):
            seen.append(list(DispatchAttempt.objects.filter(deployment=dep).values_list("outcome", "operation_id")))
            return _Answer(201)

    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=Watching().factory) == dispatch.SETTLED
    finding = Finding.objects.get(deployment=dep)
    assert seen == [[(DispatchAttempt.Outcome.SENDING, dispatch.operation_id(finding, "jira"))]]
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.attempts) == (DispatchAttempt.Outcome.SENT, 1)


def test_a_request_has_a_total_deadline():
    """(connect, read) bounds each socket operation, not the whole: a server that
    drips a byte at a time held a push for 40 s. The transport stops waiting at its
    deadline, and what it raises is an uncertain outcome, not a failure."""
    from assurance.connectors.base import (
        DeadlineExceeded,
        OutcomeUnknown,
        RequestsTransport,
        classify_transport_error,
    )

    transport = RequestsTransport(deadline=0.2)
    began = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        transport.within_deadline(time.sleep, 3)
    assert time.monotonic() - began < 1.0
    assert classify_transport_error(DeadlineExceeded("x")) is OutcomeUnknown
    assert RequestsTransport().deadline == 30.0
    with override_settings(ASSURANCE_CONNECTOR_DEADLINE_SECONDS=7):
        assert RequestsTransport().deadline == 7.0


def test_a_claim_outlasts_the_longest_step_a_live_run_can_take():
    """Between two checks a live run does at most a look (which starts no request
    once a deadline has passed: two deadlines), one create or comment, and four
    database waits; its claim must outlast that with room to spare, or a second
    runner takes the dispatch over from a runner that is still pushing."""
    assert dispatch.worst_step_seconds() == 3 * 30.0 + 4 * 20.0
    assert dispatch.CLAIM_SECONDS - dispatch.CLAIM_RENEW_AFTER >= 1.5 * dispatch.worst_step_seconds()
    assert dispatch.CLAIM_RENEW_AFTER <= dispatch.worst_step_seconds() / 2


# ------------------------------------------- the check is the last thing before


@with_key
def test_a_lift_that_commits_while_the_run_brings_the_decision_current_stops_the_push(monkeypatch):
    """current_decision() may wait on the row lock a lift holds. The lift commits
    meanwhile; the check comes after, so nothing is sent under the lifted pause."""
    from assurance import decision as decision_module

    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=2, severity="low")
    _opted_in(dep, min_severity="low")
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    real = decision_module.current_decision
    lifted = []

    def lifted_while_waiting(deployment):
        if not lifted:
            lifted.append(recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False))
        return real(deployment)

    monkeypatch.setattr(decision_module, "current_decision", lifted_while_waiting)
    connector = HeldConnector()
    connector.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert lifted and lifted[0] not in dispatch._BLOCKING_DECISIONS
    assert connector.started == 0
    assert not DispatchAttempt.objects.filter(deployment=dep).exists()


@with_key
def test_a_policy_switched_off_mid_run_stops_the_pushes_and_settles(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )

    class SwitchedOff(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            DispatchPolicy.objects.filter(deployment=dep).update(enabled=False)
            return _Answer(201)

    connector = SwitchedOff()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert connector.started == 1
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


# --------------------------------------------------------- a pause lifted onto a block


@with_key
def test_a_lift_onto_another_blocking_decision_pushes_under_it():
    """The pause's push failed; the lift lands on NEEDS_REMEDIATION, still blocking
    and still opted in. The finding is pushed under the decision in force -- it was
    set aside as "epoch moved", with nothing pushed and nothing owed."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    down = HeldConnector(status=503)
    down.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=down.factory) == dispatch.OWED
    decision = recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=False, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    assert decision == Deployment.Decision.NEEDS_REMEDIATION
    up = HeldConnector()
    up.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=up.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.policy_epoch) == (
        DispatchAttempt.Outcome.SENT, Deployment.Decision.NEEDS_REMEDIATION
    )
    assert up.started == 1


@with_key
def test_what_settles_a_row_and_what_keeps_it_owed():
    """SENT, and a binding disabled or never configured, settle. A missing key keeps
    it owed (it is a fault to fix, not a choice), and so does a refusal to cross an
    authority boundary."""
    admin = _admin()
    for outcome, owed in (
        (DispatchAttempt.Outcome.SENT, False),
        (DispatchAttempt.Outcome.SKIPPED_DISABLED, False),
        (DispatchAttempt.Outcome.SKIPPED_INERT, False),
        (DispatchAttempt.Outcome.SKIPPED_NO_KEY, True),
        (DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED, True),
        (DispatchAttempt.Outcome.FAILED, True),
        (DispatchAttempt.Outcome.UNKNOWN, True),
        (DispatchAttempt.Outcome.SENDING, True),
    ):
        assert (outcome in dispatch._UNDONE) is owed, outcome
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    ConnectorBinding.objects.filter(deployment=dep).update(enabled=False)
    assert dispatch.run_blocking_decision_dispatch(dep.pk) == dispatch.SETTLED
    with override_settings(ASSURANCE_CREDENTIAL_KEY=""):
        other = _scanned(admin)
        _findings(other, count=1)
        binding = ConnectorBinding(
            deployment=other, connector="jira", enabled=True,
            endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
        )
        binding.save()
        DispatchPolicy.objects.create(deployment=other, enabled=True, min_severity="high", on_blocking_decision=True)
        recompute_decision(
            Deployment.objects.get(pk=other.pk), paused=True,
            also_in_transaction=dispatch.record_blocking_dispatch_owed,
        )
        assert dispatch.run_blocking_decision_dispatch(other.pk) == dispatch.OWED
    assert "skipped_no_key" in DecisionDispatchDue.objects.get(deployment=other).last_error


# ---------------------------------------------- something owed, or nothing started


@with_key
def test_a_stop_that_owes_nothing_starts_nothing_and_a_lift_settles_what_was_owed(
    django_capture_on_commit_callbacks, monkeypatch
):
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    client = _client(admin)
    plain = _scanned(admin)
    with django_capture_on_commit_callbacks(execute=True):
        assert _paused_via_route(client, plain).status_code == 200
    assert started == [], "a deployment owing nothing started a background run"

    dep = _scanned(admin)
    _findings(dep, count=1, severity="low")
    _opted_in(dep, min_severity="low")
    with django_capture_on_commit_callbacks(execute=True):
        _paused_via_route(client, dep)
    assert started == [dep.pk]
    with django_capture_on_commit_callbacks(execute=True):
        lift = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json")
    assert lift.json()["decision"] not in dispatch._BLOCKING_DECISIONS
    # The lift owes nothing, but a dispatch owed before is still there to settle.
    assert started == [dep.pk, dep.pk]
    assert dispatch.run_blocking_decision_dispatch(dep.pk) == dispatch.SETTLED
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_a_stop_never_waits_on_the_run_cap_and_the_waiting_threads_are_bounded(
    django_capture_on_commit_callbacks, monkeypatch
):
    released = threading.Event()

    def run(deployment_id, *, transport_factory=None, token=None):
        released.wait(HOLD)
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    admin = _admin()
    client = _client(admin)
    deps = []
    for _ in range(8):
        dep = _scanned(admin)
        _findings(dep, count=1)
        _opted_in(dep)
        deps.append(dep)
    _warm(client, deps[0])
    with override_settings(ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS=2, ASSURANCE_DISPATCH_MAX_WAITING_RUNS=3):
        took = []
        for dep in deps:
            began = time.monotonic()
            with django_capture_on_commit_callbacks(execute=True):
                assert _paused_via_route(client, dep).status_code == 200
            took.append(time.monotonic() - began)
        assert max(took) < PROMPT, took
        # Two running, three waiting; the other three were not started -- they are
        # recorded as owed, for the sweeper.
        assert len(_background()) == 5
        assert DecisionDispatchDue.objects.filter(deployment__in=deps).count() == 8
        released.set()
        _settle()


# ------------------------------------------------------------------ the sweeper


def test_the_sweeper_starts_what_no_live_runner_holds(monkeypatch):
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    free, lapsed, held = _scanned(admin), _scanned(admin), _scanned(admin)
    now = timezone.now()
    DecisionDispatchDue.objects.create(deployment=free, owed_since=now - timedelta(minutes=3))
    DecisionDispatchDue.objects.create(
        deployment=lapsed, owed_since=now - timedelta(minutes=2), running_until=now - timedelta(seconds=1),
        run_token="dead",
    )
    DecisionDispatchDue.objects.create(
        deployment=held, owed_since=now - timedelta(minutes=1), running_until=now + timedelta(minutes=1),
        run_token="alive",
    )
    assert dispatch.sweep_owed_blocking_dispatches() == [free.pk, lapsed.pk]
    assert started == [free.pk, lapsed.pk]
    DecisionDispatchDue.objects.filter(deployment__in=[free, lapsed]).update(running_until=None, run_token="")
    with override_settings(ASSURANCE_AUTO_DISPATCH_ENABLED=False):
        assert dispatch.sweep_owed_blocking_dispatches() == []
    assert started == [free.pk, lapsed.pk]


def test_the_sweeper_starts_in_the_serving_process_on_its_first_request_and_never_at_import(monkeypatch):
    """Never at import: a pre-forking server imports the WSGI module in its master
    and forks the workers from it. On the first request of each process instead,
    once per process id."""
    import importlib

    ensured = []
    monkeypatch.setattr(dispatch, "ensure_owed_sweeper", lambda: ensured.append(1))
    wsgi = importlib.import_module("config.wsgi")
    assert ensured == [], "importing the WSGI entry point started something"
    monkeypatch.setattr(wsgi, "_application", lambda environ, start_response: ["ok"])
    assert wsgi.application({}, None) == ["ok"] and ensured == [1]
    asgi = importlib.import_module("config.asgi")
    assert ensured == [1]

    async def inner(scope, receive, send):
        return "ok"

    monkeypatch.setattr(asgi, "_application", inner)
    import asyncio

    assert asyncio.run(asgi.application({"type": "http"}, None, None)) == "ok" and ensured == [1, 1]


def test_one_sweeper_per_process_that_sweeps_soon_after_it_starts(monkeypatch):
    ran = threading.Event()
    waits = []
    monkeypatch.setattr(dispatch, "sweep_owed_blocking_dispatches", lambda: ran.set() or [])
    # The sweeper of the process this one was forked from: not this process's.
    monkeypatch.setattr(dispatch, "_SWEEPER", [(-1, None)])

    class Stop:
        def __init__(self):
            self.event = threading.Event()

        def wait(self, seconds):
            waits.append(seconds)
            return self.event.wait(0.01 if len(waits) == 1 else 5)

        def set(self):
            self.event.set()

        def is_set(self):
            return self.event.is_set()

    stop = Stop()
    monkeypatch.setattr(dispatch, "_SWEEP_STOP", stop)
    with override_settings(ASSURANCE_DISPATCH_SWEEP_SECONDS=0):
        assert dispatch.start_owed_sweeper() is False
        # Off, and known to be: every request after takes the fast path.
        assert dispatch._SWEEPER == [(os.getpid(), None)]
    try:
        with override_settings(ASSURANCE_DISPATCH_SWEEP_SECONDS=300):
            assert dispatch.start_owed_sweeper() is True
            assert dispatch.start_owed_sweeper() is False
            dispatch.ensure_owed_sweeper()
            assert len(dispatch._SWEEPER) == 1
        assert ran.wait(5), "the sweeper never swept"
        pid, sweeper = dispatch._SWEEPER[0]
        assert pid == os.getpid() and sweeper.daemon and sweeper.name == dispatch.SWEEPER_THREAD
        # The first sweep comes a few seconds after the start, not a whole interval.
        assert waits[0] == dispatch.FIRST_SWEEP_AFTER == 5.0
        assert waits[1] == 300
    finally:
        stop.set()
        for _pid, thread in dispatch._SWEEPER:
            if thread is not None:
                thread.join(5)


def test_the_sweeper_survives_a_connection_that_will_not_close(monkeypatch):
    sweeps = []
    monkeypatch.setattr(dispatch, "sweep_owed_blocking_dispatches", lambda: sweeps.append(1) or [])

    def broken():
        raise OperationalError("cannot close")

    monkeypatch.setattr(dispatch.connections, "close_all", broken)

    class Stop:
        def wait(self, seconds):
            return len(sweeps) >= 3

    dispatch._sweeper(0.01, Stop())
    assert len(sweeps) == 3


def test_the_sweeper_closes_its_own_connection(monkeypatch):
    used = []

    def sweep():
        Deployment.objects.exists()
        used.append(connections["default"])
        return []

    monkeypatch.setattr(dispatch, "sweep_owed_blocking_dispatches", sweep)

    class Stop:
        def wait(self, seconds):
            return bool(used)

    thread = threading.Thread(target=dispatch._sweeper, args=(0.01, Stop()))
    thread.start()
    thread.join(10)
    assert used and used[0].connection is None, "the sweeper left its connection open"


@with_key
def test_an_issue_the_system_already_has_is_reused_not_created_again():
    """No attempt records it -- a manual push, a restored database -- but the system
    has an issue for the finding: it is recorded as sent, and nothing is created."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep, connector="github_issues")
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    remote = FakeRemote()
    remote.add("12", Finding.objects.get(deployment=dep), kind="github")
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.external_ref, remote.creates) == (DispatchAttempt.Outcome.SENT, "12", 0)


@with_key
def test_a_push_after_a_reconciliation_is_uncertain_again_until_its_end_is_known():
    """An attempt reconciled once (absent, so FAILED) is pushed again, and that
    runner dies mid-push. The earlier reconciliation says nothing about the new
    request: the next runner must look again, not push blind."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    _lost(dep, age=dispatch.CLAIM_SECONDS + 1)
    remote = FakeRemote()
    remote.crash = True
    with pytest.raises(Crash):
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory, token="dead")
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert attempt.outcome == DispatchAttempt.Outcome.SENDING and attempt.is_uncertain
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=timezone.now() - timedelta(seconds=1))
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1


@with_key
def test_a_look_that_fails_is_not_taken_for_absent():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    _lost(dep, age=dispatch.CLAIM_SECONDS + 1)

    class Unreachable(FakeRemote):
        def get(self, url, *, headers, params=None):
            raise ConnectionError("jira is unreachable")

    remote = Unreachable()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    assert remote.creates == 0
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.UNKNOWN


# ============================================================ round 3

# ------------------------------------------------------------------ fork safety


def test_a_forked_child_starts_afresh_whatever_the_parent_held():
    """A pre-forking server forks workers while this process's threads may hold
    its locks and run slots. The child gets fresh ones -- a lock held at the fork
    would be held for ever there, and every stop that starts a dispatch would hang
    on it -- no jobs, and no sweeper: it starts its own."""
    held, release = threading.Event(), threading.Event()

    def hold():
        with dispatch._JOBS_LOCK:
            held.set()
            release.wait(10)

    holder = threading.Thread(target=hold)
    holder.start()
    assert held.wait(5)
    slots = dispatch._run_slots()
    taken = [slots.acquire(timeout=1) for _ in range(dispatch._max_concurrent_runs())]
    dispatch._JOBS[777] = False
    dispatch._SWEEPER[:] = [(os.getpid(), holder)]
    read, write = os.pipe()
    try:
        pid = os.fork()
        if pid == 0:  # the child: no database, no Django request -- only this module's state
            try:
                ok = [
                    dispatch._JOBS_LOCK.acquire(timeout=2),
                    dispatch._JOBS == {},
                    dispatch._run_slots().acquire(timeout=2),
                    dispatch._SWEEPER == [],
                    not dispatch._SWEEP_STOP.is_set(),
                ]
                os.write(write, ("".join("1" if x else "0" for x in ok)).encode())
            finally:
                os._exit(0)
        os.close(write)
        answer = os.read(read, 16).decode()
        os.waitpid(pid, 0)
    finally:
        release.set()
        holder.join(5)
        for got in taken:
            if got:
                slots.release()
        dispatch._JOBS.pop(777, None)
        dispatch._SWEEPER.clear()
        os.close(read)
    assert answer == "11111", answer


# ------------------------------------------- a stop that could not record it


@with_key
def test_a_dispatch_its_stop_could_not_record_is_started_past_the_bound_and_recorded_first(
    django_capture_on_commit_callbacks, monkeypatch
):
    """The bound on waiting runs is full, and the stop could not write its record:
    nothing else will ever know this dispatch is owed. It is started anyway, and
    its thread records it before it waits for a slot."""
    released = threading.Event()

    def run(deployment_id, *, transport_factory=None, token=None):
        released.wait(HOLD)
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    monkeypatch.setattr(dispatch, "_record_owed_if_missing", lambda pk: seen_record.append(pk))
    seen_record = []
    admin = _admin()
    client = _client(admin)
    lost = _scanned(admin)
    _findings(lost, count=1)
    _opted_in(lost)
    hog = 4848
    with override_settings(ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS=1, ASSURANCE_DISPATCH_MAX_WAITING_RUNS=0):
        assert dispatch.start_blocking_decision_dispatch(hog) == dispatch.STARTED
        # A recorded one past the bound: not started, counted, nothing logged.
        assert dispatch.start_blocking_decision_dispatch(4849) == dispatch.FULL
        def broken(**kwargs):
            raise DatabaseError("disk I/O error")

        monkeypatch.setattr(DecisionDispatchDue.objects, "create", broken)
        with django_capture_on_commit_callbacks(execute=True):
            assert _paused_via_route(client, lost).status_code == 200
        assert lost.pk in dispatch._JOBS, "an unrecorded dispatch was not started"
        # Recorded by its thread, which runs on its own time: waited for, bounded.
        assert _wait_for(lambda: seen_record == [lost.pk], timeout=10), seen_record
        released.set()
        _settle()


class _Stderr:
    """Stands in for the process's stderr: a pipe, read back by the test."""

    def __init__(self, fill=False):
        self.read_fd, self.write_fd = os.pipe()
        if fill:
            os.set_blocking(self.write_fd, False)
            try:
                while True:
                    os.write(self.write_fd, b"x" * 65536)
            except BlockingIOError:
                pass
            os.set_blocking(self.write_fd, True)

    def fileno(self):
        return self.write_fd

    def text(self):
        os.set_blocking(self.read_fd, False)
        chunks = []
        try:
            while True:
                chunk = os.read(self.read_fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except BlockingIOError:
            pass
        return b"".join(chunks).decode(errors="replace")

    def close(self):
        os.close(self.read_fd)
        os.close(self.write_fd)


class _Sink(logging.Handler):
    """A log handler that records which thread wrote each record to it, and can be
    made slow."""

    def __init__(self, seconds=0.0):
        super().__init__()
        self.seconds = seconds
        self.written = []

    def emit(self, record):
        self.written.append((threading.current_thread(), record.getMessage()))
        time.sleep(self.seconds)


@with_key
def test_an_unrecorded_dispatch_whose_thread_cannot_start_is_named_at_once_on_stderr_and_kept_for_the_log(
    monkeypatch, caplog
):
    """The process is out of threads and the stop could not record its dispatch:
    nothing else will ever know it is owed. The ERROR naming the command is on
    stderr before the call returns, written in this thread. This thread never
    writes it to a log handler -- a slow sink would hold the stop -- so it waits,
    queued and counted, for the log thread; once a thread can start, it is written,
    with its level, its thread and its message."""
    import sys

    from assurance import oplog

    err = _Stderr()
    sink = _Sink()
    logging.getLogger("assurance").addHandler(sink)
    kept = oplog.KEPT_FOR_WRITER[0]
    monkeypatch.setattr(sys, "__stderr__", err)
    monkeypatch.setattr(oplog, "_PUMP", [])  # no log thread in this process: it could not start either

    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    try:
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            began = time.monotonic()
            assert dispatch.start_blocking_decision_dispatch(4950, unrecorded=True) == dispatch.NOT_STARTED
            took = time.monotonic() - began
            # On stderr the moment the call returns.
            line = err.text()
            assert oplog.KEPT_FOR_WRITER[0] == kept + 1
            here = [m for t, m in sink.written if t is threading.current_thread()]
    finally:
        monkeypatch.undo()
        err.close()
    try:
        assert took < 0.1, took
        assert line.count("\n") == 1 and "retry_blocking_dispatches --deployment 4950" in line and "ERROR" in line
        assert here == [], "the stop's thread wrote to a log handler"
        # Threads can start again: the next writer writes what was kept.
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            assert oplog.start_pump()
            assert _logged(caplog, "retry_blocking_dispatches --deployment 4950")
        [record] = [r for r in caplog.records if "4950" in r.getMessage()]
        assert record.levelno == logging.ERROR and record.threadName == threading.current_thread().name
        assert "NOT recorded as owed" in record.getMessage()
        assert [t for t, m in sink.written if "4950" in m and t is threading.current_thread()] == []
    finally:
        logging.getLogger("assurance").removeHandler(sink)


@with_key
@pytest.mark.parametrize("threads", ["can start", "cannot start"])
def test_the_line_an_operator_must_see_never_waits_on_a_slow_sink_nobody_is_inside(threads, monkeypatch, caplog):
    """A log sink that takes 2 s a record, and no thread inside it: free to be
    written to, and slow. The line is on stderr at once and the call returns at
    once -- whether or not a thread can start -- because this thread never writes
    to a handler; the sink gets it from the log thread."""
    import sys

    from assurance import oplog

    err = _Stderr()
    sink = _Sink(seconds=2.0)
    logging.getLogger("assurance").addHandler(sink)
    monkeypatch.setattr(sys, "__stderr__", err)
    if threads == "cannot start":
        monkeypatch.setattr(oplog, "_PUMP", [])

        def refuse(self):
            raise RuntimeError("can't start new thread")

        monkeypatch.setattr(threading.Thread, "start", refuse)
    try:
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            began = time.monotonic()
            oplog.emit_now(logging.ERROR, "run `manage.py retry_blocking_dispatches --deployment %s`", 9)
            took = time.monotonic() - began
            line = err.text()
    finally:
        monkeypatch.undo()
        err.close()
    try:
        assert took < 0.1, took
        assert "--deployment 9" in line
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            assert oplog.start_pump()
            assert _logged(caplog, "--deployment 9", timeout=10.0)
        assert [m for t, m in sink.written if "--deployment 9" in m and t is threading.current_thread()] == []
        assert any("--deployment 9" in m for _, m in sink.written)
    finally:
        logging.getLogger("assurance").removeHandler(sink)


def test_the_line_an_operator_must_see_never_waits_on_a_full_stderr(monkeypatch, caplog):
    """stderr is a pipe nobody is reading, full: the line is not written there --
    a write would block -- and the call returns at once; the logger still has it."""
    import sys

    from assurance import oplog

    err = _Stderr(fill=True)
    monkeypatch.setattr(sys, "__stderr__", err)
    skipped = oplog.STDERR_SKIPPED[0]
    try:
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            began = time.monotonic()
            oplog.emit_now(logging.ERROR, "deployment %s: run `manage.py retry_blocking_dispatches --deployment %s`", 7, 7)
            took = time.monotonic() - began
    finally:
        monkeypatch.undo()
        err.close()
    assert took < 0.5, took
    assert oplog.STDERR_SKIPPED[0] == skipped + 1
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        assert _logged(caplog, "--deployment 7")


@with_key
def test_the_thread_of_an_unrecorded_dispatch_records_it_before_it_waits(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    dispatch._record_owed_if_missing(dep.pk)
    assert DecisionDispatchDue.objects.filter(deployment=dep).exists()


# ------------------------------------------------------------------ Jira Cloud


@with_key
@pytest.mark.parametrize("flavour", ["cloud", "dc"])
def test_the_jira_look_works_on_cloud_and_on_data_center(flavour):
    """Jira Cloud retired /rest/api/2/search (410); Data Center has no
    /rest/api/3/search/jql (404). Found means SENT, and absent -- long enough
    after -- means FAILED and pushed once, on both."""
    admin = _admin()
    for found in (True, False):
        dep = _scanned(admin)
        _findings(dep, count=1)
        _opted_in(dep)
        recompute_decision(
            Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
        )
        _lost(dep, age=dispatch.CLAIM_SECONDS + 1)
        remote = FakeRemote(jira=flavour)
        if found:
            remote.add("SEC-9", Finding.objects.get(deployment=dep))
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
        attempt = DispatchAttempt.objects.get(deployment=dep)
        assert attempt.outcome == DispatchAttempt.Outcome.SENT
        assert (attempt.external_ref, remote.creates) == (("SEC-9", 0) if found else ("SEC-1", 1))
        if found:
            assert "reconciled by looking" in attempt.reconciled_detail
        if flavour == "cloud":
            assert all(url.endswith("/rest/api/3/search/jql") for url in remote.gets)


@with_key
@pytest.mark.parametrize("status", [410, 500, 403])
def test_an_error_answer_to_a_look_is_never_read_as_absent(status):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    _lost(dep, age=dispatch.CLAIM_SECONDS + 1)

    class Refusing(FakeRemote):
        def get(self, url, *, headers, params=None):
            return _Json(status, {"errorMessages": ["no"]})

    remote = Refusing()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    assert remote.creates == 0
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.UNKNOWN


@with_key
def test_absent_is_trusted_only_once_the_attempt_is_older_than_the_claim():
    """An answer the transport stopped waiting for can still arrive for as long as
    a live runner could still be inside that step: not before the claim is up."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    _lost(dep)
    remote = FakeRemote()
    for age, pushed in ((dispatch.CLAIM_SECONDS - 10, 0), (dispatch.CLAIM_SECONDS + 10, 1)):
        DispatchAttempt.objects.filter(deployment=dep).update(updated_at=timezone.now() - timedelta(seconds=age))
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory)
        assert remote.creates == pushed, (age, remote.creates)


def test_the_look_has_a_total_deadline_too(monkeypatch):
    import requests

    from assurance.connectors.base import DeadlineExceeded, RequestsTransport

    monkeypatch.setattr(requests, "get", lambda *a, **k: time.sleep(3))
    began = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        RequestsTransport(deadline=0.2).get("https://jira.example/x", headers={}, params={})
    assert time.monotonic() - began < 1.0


# ------------------------------------------- a record that fails after the push


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "splunk"])
def test_a_push_whose_end_could_not_be_recorded_stays_uncertain_and_is_not_pushed_again(connector_name, monkeypatch):
    """The push landed; recording how it ended failed (the database was locked).
    It must not become FAILED, which would license a second push: it stays SENDING,
    and is settled by looking (Jira) or held (Splunk). One issue, one event."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep, connector=connector_name)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    real_save = DispatchAttempt.save
    armed = [1]

    def flaky(self, *args, **kwargs):
        fields = kwargs.get("update_fields") or []
        if armed[0] and "outcome" in fields and self.outcome != DispatchAttempt.Outcome.SENDING:
            armed[0] = 0
            raise OperationalError("database is locked")
        return real_save(self, *args, **kwargs)

    monkeypatch.setattr(DispatchAttempt, "save", flaky)
    remote = FakeRemote()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.SENDING
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=None, run_token="")
    DispatchAttempt.objects.filter(deployment=dep).update(
        updated_at=timezone.now() - timedelta(seconds=dispatch.CLAIM_SECONDS + 1)
    )
    outcome = dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory)
    assert remote.creates == 1
    if connector_name == "jira":
        assert outcome == dispatch.SETTLED
        assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.SENT
    else:
        assert outcome == dispatch.OWED


# ---------------------------------------------------------------------- markers


@with_key
def test_github_without_push_access_is_found_again_by_the_marker_in_the_body():
    """GitHub silently drops the labels of a token without push access. The create
    says so, and when an answer is lost the issue is found by its body instead of
    being created twice."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep, connector="github_issues")
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    remote = FakeRemote()
    remote.drop_labels = True
    remote.crash = True
    with pytest.raises(Crash):
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory, token="dead")
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=timezone.now() - timedelta(seconds=1))
    DispatchAttempt.objects.filter(deployment=dep).update(
        updated_at=timezone.now() - timedelta(seconds=dispatch.CLAIM_SECONDS + 1)
    )
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1
    assert DispatchAttempt.objects.get(deployment=dep).external_ref == "1"

    # And a create whose labels were dropped says so, with the number recorded.
    other = _scanned(admin)
    _findings(other, count=1)
    _opted_in(other, connector="github_issues")
    recompute_decision(
        Deployment.objects.get(pk=other.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    assert dispatch.run_blocking_decision_dispatch(other.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=other)
    assert attempt.external_ref == "2" and "marker label did not stick" in attempt.detail


def _owed_pause(admin, connector="jira", count=1):
    dep = _scanned(admin)
    _findings(dep, count=count)
    _opted_in(dep, connector=connector)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    return dep


_KIND = {"jira": "jira", "github_issues": "github", "servicenow": "servicenow"}
_REF = {"jira": "SEC-99", "github_issues": "99", "servicenow": "sys99"}


@with_key
@pytest.mark.parametrize("path", ["first push", "uncertain push"])
@pytest.mark.parametrize("connector_name", ["github_issues", "jira"])
def test_a_closed_issue_is_commented_on_and_recorded_apart_as_the_tracker_saying_done(connector_name, path, caplog):
    """The finding's issue exists, and the tracker has closed it, while the finding
    is part of a blocking decision again. It is not reopened and not filed twice:
    it is commented on, and recorded SENT_TO_CLOSED -- with a WARNING, and a note
    the operator reads on the attempt -- on the first push and on the uncertain
    push's path alike."""
    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    ref = _REF[connector_name]
    remote.add(ref, finding, closed=True, kind=_KIND[connector_name])
    if path == "uncertain push":
        _lost(dep, connector_name, outcome=DispatchAttempt.Outcome.SENDING)
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.external_ref) == (DispatchAttempt.Outcome.SENT_TO_CLOSED, ref)
    assert attempt.is_terminal
    assert f"the tracker says this is done: {connector_name} issue {ref} is closed" in attempt.detail
    assert "decision (paused) blocks on this finding; commented on it; it is not reopened" in attempt.detail
    assert remote.creates == 0 and len(remote.comments) == 1 and ref in remote.comments[0][0]
    assert f"the tracker says this is done: {connector_name} issue {ref} is closed" in caplog.text
    # Found where it is read from the repository at once -- the issues list, all
    # states -- not only by the search, whose index lags.
    assert not any(url.endswith("/search/issues") for url in remote.gets)
    # The operator reads it apart from SENT.
    state = _client(admin).get(f"/api/assurance/deployments/{dep.uuid}/dispatch-attempts/").json()
    assert [a["outcome"] for a in state["attempts"]] == ["sent_to_closed"]


@with_key
def test_a_comment_on_a_closed_issue_that_fails_says_so():
    admin = _admin()
    dep = _owed_pause(admin)
    remote = FakeRemote()
    remote.add("SEC-99", Finding.objects.get(deployment=dep), closed=True)

    real_post = remote.post

    def post(url, *, headers, json):
        if url.endswith("/comment"):
            return _Json(403, {"errorMessages": ["no comment permission"]})
        return real_post(url, headers=headers, json=json)

    remote.post = post
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert attempt.outcome == DispatchAttempt.Outcome.SENT_TO_CLOSED
    assert "the comment on it failed (jira error 403" in attempt.detail and "commented on it" not in attempt.detail
    assert remote.creates == 0


@with_key
def test_a_closed_servicenow_record_is_recorded_as_the_tracker_saying_done():
    """ServiceNow reads ``active=false`` as closed; it takes no comment here, and
    says so."""
    admin = _admin()
    dep = _owed_pause(admin, "servicenow")
    remote = FakeRemote()
    remote.add("sys99", Finding.objects.get(deployment=dep), closed=True, kind="servicenow")
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.external_ref) == (DispatchAttempt.Outcome.SENT_TO_CLOSED, "sys99")
    assert "servicenow takes no comment here" in attempt.detail
    assert remote.creates == 0


# ------------------------------------------------ installation and its markers


@with_key
def test_the_installation_id_is_random_persisted_never_the_secret_key_and_the_setting_overrides_it():
    from assurance.markers import identity
    from assurance.models import AssuranceInstallation, AssuranceInstallationId

    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    finding = Finding.objects.get(deployment=dep)
    row = AssuranceInstallation.objects.get(pk=1)
    assert len(row.installation_id) == 32 and len(row.marker_secret) == 64 and row.created_at is not None
    here = _ours(finding)
    assert identity().installation_id == row.installation_id
    assert len(here.label) == 50 and here.label.endswith(str(finding.uuid)) and len(here.tag) == 32
    # Rotating the secret key changes nothing.
    with override_settings(SECRET_KEY="rotated-" + "k" * 40):
        assert _ours(finding) == here
    # The setting overrides the persisted id, label and tag alike -- and every id
    # used is kept, the persisted one with it.
    with override_settings(ASSURANCE_INSTALLATION_ID="prod-eu-1"):
        there = _ours(finding)
        assert identity().all_ids() == ("prod-eu-1", row.installation_id)
    assert there.label != here.label and there.tag != here.tag and there.label.endswith(str(finding.uuid))
    kept = set(AssuranceInstallationId.objects.values_list("installation_id", flat=True))
    assert kept == {row.installation_id, "prod-eu-1"}
    # Created on first use when no migration made it.
    AssuranceInstallation.objects.all().delete()
    fresh = identity()
    assert fresh.installation_id != row.installation_id and AssuranceInstallation.objects.count() == 1


@with_key
def test_the_tag_binds_the_connector_and_its_destination():
    """The same finding's tag for another tracker, another repository, project or
    table, or another base URL, is another tag: one read in one tracker never
    verifies in another. Case and a trailing slash are not another destination."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    finding = Finding.objects.get(deployment=dep)
    tags = {
        "jira": _ours(finding, "jira").tag,
        "jira, another project": _ours(finding, "jira", endpoint={"base_url": "https://jira.example", "project_key": "OPS"}).tag,
        "jira, another host": _ours(finding, "jira", endpoint={"base_url": "https://jira.other", "project_key": "SEC"}).tag,
        "github": _ours(finding, "github_issues").tag,
        "github, another repository": _ours(
            finding, "github_issues", endpoint={"base_url": "https://api.github.example", "owner": "acme", "repo": "web"}
        ).tag,
        "servicenow": _ours(finding, "servicenow").tag,
        "servicenow, another table": _ours(finding, "servicenow", endpoint={"base_url": "https://sn.example", "table": "problem"}).tag,
    }
    assert len(set(tags.values())) == len(tags), tags
    same = _ours(finding, "jira", endpoint={"base_url": "https://JIRA.example/", "project_key": "sec"})
    assert same.tag == tags["jira"]
    # The label is the installation's, the same everywhere: what a look searches on.
    assert _ours(finding, "jira").label == _ours(finding, "github_issues").label


@with_key
def test_a_secret_key_rotation_creates_no_second_ticket():
    """Pushed, the answer lost; then the secret key is rotated. The look still
    finds the issue: one ticket."""
    admin = _admin()
    dep = _owed_pause(admin)
    remote = FakeRemote()
    remote.crash = True
    with pytest.raises(Crash):
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory, token="dead")
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=None, run_token="")
    DispatchAttempt.objects.filter(deployment=dep).update(updated_at=timezone.now() - timedelta(days=1))
    with override_settings(SECRET_KEY="rotated-" + "k" * 40):
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.external_ref, remote.creates) == (DispatchAttempt.Outcome.SENT, "SEC-1", 1)
    assert remote.for_finding(Finding.objects.get(deployment=dep)) == ["SEC-1"]


def _older(finding, connector, form):
    """An issue an earlier release made for ``finding``, before this installation
    wrote tags, in ``form``: ``(kind, ref, fields)`` for :meth:`FakeRemote.add`."""
    before = _installed_at() - timedelta(days=30)
    uuid = str(finding.uuid)
    text = f"Severity: high\n\nAthena finding: {uuid}"
    if connector == "servicenow":
        return "servicenow", "sys-old", {"correlation_id": uuid, "body": text, "created": before}
    kind = _KIND[connector]
    ref = "SEC-900" if kind == "jira" else "900"
    labels = {
        "master": ["athena", "severity-high"],
        "round 2": ["athena", f"athena-{uuid}"],
        "round 3": ["athena", f"athena-3c9e1a-{uuid}"],
        "bare uuid label": ["athena", uuid],
    }[form]
    body = {
        "round 3": f"{text}\nAthena marker: athena-3c9e1a-{uuid}",
        # A body someone edited: the label is all that is left.
        "bare uuid label": "edited by hand",
    }.get(form, text)
    return kind, ref, {"labels": labels, "body": body, "created": before}


_FORMS = [
    ("jira", "master"), ("jira", "round 2"), ("jira", "round 3"), ("jira", "bare uuid label"),
    ("github_issues", "master"), ("github_issues", "round 2"), ("github_issues", "round 3"),
    ("github_issues", "bare uuid label"), ("servicenow", "master"),
]


@with_key
@pytest.mark.parametrize("connector_name,form", _FORMS)
@pytest.mark.parametrize("attempt", ["uncertain", "none (a manual push)"])
def test_an_issue_in_an_older_format_is_never_adopted_and_the_new_ticket_names_it(connector_name, form, attempt, caplog):
    """An earlier release may have pushed the finding -- leaving the attempt
    uncertain, or recording none at all (a manual push) -- or somebody edited an old
    issue to mention it: which, cannot be told, since anyone who can edit an issue
    can write any older format into it, today. The look finds it, whatever that
    format; it is never adopted and never holds the dispatch. One ticket is filed,
    naming it -- in its body, on the attempt and in a WARNING: a possible duplicate,
    named; never a lost ticket."""
    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    kind, ref, fields = _older(finding, connector_name, form)
    remote.add(ref, kind=kind, **fields)
    if attempt == "uncertain":
        _lost(dep, connector_name, carried=False, age=86400)
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
        named = f"Possible duplicate: {connector_name} issue(s) {ref},"
        assert _logged(caplog, named)
    row = DispatchAttempt.objects.get(deployment=dep)
    assert row.outcome == DispatchAttempt.Outcome.SENT and row.external_ref not in ("", ref)
    assert remote.creates == 1 and named in remote.issues[-1]["body"] and named in row.detail
    assert remote.for_finding(finding) == [ref, row.external_ref]
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "github_issues", "servicenow"])
def test_an_older_format_issue_the_attempt_records_is_the_one_adopted_without_a_tag(connector_name):
    """An earlier release's push whose attempt records its issue: that issue --
    read directly by its id -- is the finding's. Nothing is filed."""
    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    kind, ref, fields = _older(finding, connector_name, "master")
    remote.add(ref, kind=kind, **fields)
    _lost(dep, connector_name, carried=False, age=86400, ref=ref)
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    row = DispatchAttempt.objects.get(deployment=dep)
    assert (row.outcome, row.external_ref, remote.creates) == (DispatchAttempt.Outcome.SENT, ref, 0)


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "github_issues", "servicenow"])
def test_an_uncertain_push_an_earlier_release_made_is_held_not_pushed_when_nothing_is_found(connector_name):
    """Its push carried a marker this look cannot verify, and nothing is found:
    "absent" is not trusted for it. Held -- for a person -- and never pushed again
    blind; the reconcile command settles it."""
    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    attempt = _lost(dep, connector_name, carried=False, age=86400)
    remote = FakeRemote()
    for _ in range(2):
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN and attempt.is_uncertain
    assert "held, not pushed again: it was pushed by an earlier release" in attempt.detail
    assert f"reconcile_dispatch_attempt {attempt.uuid}" in attempt.detail
    assert remote.creates == 0
    call_command(
        "reconcile_dispatch_attempt", str(attempt.uuid), "--provider-lacks-it", "--by", "ops", stdout=io.StringIO()
    )
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1


_PLANTS = [
    "label only", "body only, untagged", "a forged tag", "another installation's", "older format, new", "closed",
    "another tracker's tag", "another destination's tag",
]
#: For each connector: another connector, and the same one at another destination.
_ELSEWHERE = {
    "jira": ("github_issues", {"base_url": "https://jira.example", "project_key": "OPS"}),
    "github_issues": ("jira", {"base_url": "https://api.github.example", "owner": "acme", "repo": "web"}),
    "servicenow": ("jira", {"base_url": "https://sn.example", "table": "problem"}),
}


@with_key
@pytest.mark.parametrize(
    "connector_name,plant",
    # ServiceNow records carry no labels.
    [(c, p) for c in ("jira", "github_issues", "servicenow") for p in _PLANTS if (c, p) != ("servicenow", "label only")],
)
def test_an_issue_somebody_else_wrote_is_never_adopted_and_never_holds_the_dispatch(connector_name, plant, caplog):
    """Anyone who can open an issue can write a body, and anyone with triage
    rights can copy a label. Neither can write the tag -- and a tag read in another
    tracker, or at another destination of this one, does not verify here. An issue
    carrying the marker without a tag that verifies -- or in an older format, but
    created after this installation began tagging -- is ignored, named in a
    WARNING, and the finding's own issue is created."""
    from assurance.markers import Identity

    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    ours = _ours(finding, connector_name)
    theirs = _ours(finding, connector_name, Identity("staging", "another secret", None))
    other_connector, other_endpoint = _ELSEWHERE[connector_name]
    copied = {
        "another tracker's tag": _ours(finding, other_connector),
        "another destination's tag": _ours(finding, connector_name, endpoint=other_endpoint),
    }.get(plant)
    kind = _KIND[connector_name]
    uuid = str(finding.uuid)
    fields = {
        "label only": {"labels": [ours.label], "body": "planted"},
        "body only, untagged": {"labels": [], "body": f"unrelated. Athena marker: {ours.label}"},
        "a forged tag": {"labels": [ours.label], "body": f"Athena marker: {ours.label} {'0' * 32}"},
        "another installation's": {"labels": [theirs.label], "body": f"Athena finding: {uuid}\n{theirs.body_line}"},
        "older format, new": {"labels": [f"athena-{uuid}"], "body": f"Athena finding: {uuid}"},
        "closed": {"labels": [ours.label], "body": f"Athena marker: {ours.label}", "closed": True},
        "another tracker's tag": {"labels": [ours.label], "body": f"Athena finding: {uuid}\n{copied.body_line if copied else ''}"},
        "another destination's tag": {"labels": [ours.label], "body": f"Athena finding: {uuid}\n{copied.body_line if copied else ''}"},
    }[plant]
    if kind == "servicenow":
        display = {
            "a forged tag": f"{ours.label} {'0' * 32}", "another installation's": theirs.text,
            "another tracker's tag": copied.text if copied else None,
            "another destination's tag": copied.text if copied else None,
        }.get(plant)
        fields = {"body": fields["body"], "closed": fields.get("closed", False), "correlation_id": uuid, "display": display}
    planted = {"jira": "EVIL-1", "github": "700", "servicenow": "sys-evil"}[kind]
    remote = FakeRemote()
    remote.add(planted, kind=kind, **fields)
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert attempt.outcome == DispatchAttempt.Outcome.SENT and attempt.external_ref != planted
    assert remote.creates == 1 and remote.comments == []
    assert "not this installation's" in caplog.text and planted in caplog.text


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "github_issues", "servicenow"])
def test_copies_of_the_findings_issue_never_hide_it_and_never_hold_it(connector_name, caplog):
    """The finding's issue, then 150 planted issues and 120 copies of it -- tag and
    all (a Jira clone, a pasted body), each made after it. The look reads page after
    page, oldest first; the first issue whose tag verifies is the original, and it
    is adopted. Nothing is held and nothing is created."""
    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    kind = _KIND[connector_name]
    remote = FakeRemote()
    t0 = _installed_at() + timedelta(minutes=1)
    for n in range(150):
        remote.add(f"{'EVIL-' if kind == 'jira' else ''}{1000 + n}" if kind != "servicenow" else f"sysx{n}", kind=kind,
                   labels=[_marker(dep)], body="planted", correlation_id=str(finding.uuid),
                   created=t0 + timedelta(seconds=n))
    original = {"jira": "SEC-5", "github": "5", "servicenow": "sys5"}[kind]
    remote.add(original, finding, kind=kind, created=t0 + timedelta(minutes=10))
    body = remote.issues[-1]
    for n in range(120):
        copy = dict(body, key=f"{'CPY-' if kind == 'jira' else ''}{2000 + n}" if kind != "servicenow" else f"sysc{n}",
                    created=t0 + timedelta(minutes=11, seconds=n))
        remote.issues.append(copy)
    _lost(dep, connector_name, outcome=DispatchAttempt.Outcome.SENDING, age=dispatch.CLAIM_SECONDS + 1)
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.external_ref, remote.creates) == (DispatchAttempt.Outcome.SENT, original, 0)
    assert len(remote.gets) >= 2, "it did not page"
    assert "150 issue(s) matched" in caplog.text


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "github_issues", "servicenow"])
def test_the_issue_recorded_for_the_finding_is_read_directly_however_many_copies_exist(connector_name):
    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    kind = _KIND[connector_name]
    remote = FakeRemote()
    recorded = {"jira": "SEC-1", "github": "1", "servicenow": "sys1"}[kind]
    remote.add(recorded, finding, kind=kind, created=_installed_at() + timedelta(minutes=1))
    for n in range(300):
        remote.add(f"{'CPY-' if kind == 'jira' else ''}{3000 + n}" if kind != "servicenow" else f"sysc{n}",
                   finding, kind=kind, created=_installed_at() - timedelta(minutes=5))
    _lost(dep, connector_name, ref=recorded, age=dispatch.CLAIM_SECONDS + 1)
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.external_ref, remote.creates) == (DispatchAttempt.Outcome.SENT, recorded, 0)
    assert len(remote.gets) == 1 and remote.gets[0].endswith(f"/{recorded}")


@with_key
def test_several_issues_in_an_older_format_never_hold_the_dispatch_and_the_new_ticket_names_them(caplog):
    """Two old issues that mention the finding -- an earlier release's, or two
    somebody edited to mention it: which is its own cannot be told, and neither is
    adopted. Nothing is held: one ticket is filed that names both, and the next run
    files no other."""
    admin = _admin()
    dep = _owed_pause(admin)
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    before = _installed_at() - timedelta(days=3)
    for ref in ("SEC-1", "SEC-77"):
        remote.add(ref, labels=["athena"], body=f"Athena finding: {finding.uuid}", created=before)
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        for _ in range(2):
            assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
        assert _logged(caplog, "Possible duplicate: jira issue(s) SEC-1, SEC-77,")
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert attempt.outcome == DispatchAttempt.Outcome.SENT and attempt.external_ref == "SEC-3"
    assert remote.creates == 1 and "Possible duplicate: jira issue(s) SEC-1, SEC-77," in remote.issues[-1]["body"]


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "github_issues", "servicenow"])
@pytest.mark.parametrize("before,after", [(None, "prod-eu-1"), ("prod-eu-1", "prod-eu-2")])
def test_setting_or_changing_the_installation_id_after_go_live_files_no_second_ticket(connector_name, before, after):
    """Pushed by hand under one installation id -- the manual route records no
    attempt -- and then ``ASSURANCE_INSTALLATION_ID`` is set, or changed. Every id
    this database has used is kept, and a marker made under any of them verifies:
    the look finds the issue, and nothing is filed again."""
    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    binding = ConnectorBinding.objects.get(deployment=dep, connector=connector_name)
    with override_settings(ASSURANCE_INSTALLATION_ID=before or ""):
        assert binding.build_connector().push_finding(finding, transport=remote).ok
    ref = remote.issues[-1]["key"]
    with override_settings(ASSURANCE_INSTALLATION_ID=after):
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert (attempt.outcome, attempt.external_ref, remote.creates) == (DispatchAttempt.Outcome.SENT, ref, 1)


@with_key
def test_a_database_given_a_new_identity_is_another_installation():
    """A database restored into another environment is the same installation until
    it is given a new identity (the README's reset): then it adopts none of the
    first one's issues."""
    from assurance.models import AssuranceInstallation, AssuranceInstallationId

    admin = _admin()
    dep = _owed_pause(admin)
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    remote.add("SEC-5", finding)
    AssuranceInstallationId.objects.all().delete()
    AssuranceInstallation.objects.all().delete()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1 and DispatchAttempt.objects.get(deployment=dep).external_ref != "SEC-5"


@with_key
@pytest.mark.parametrize("connector_name", ["jira", "github_issues", "servicenow"])
def test_a_lost_push_whose_issue_is_absent_is_pushed_once_and_never_held(connector_name):
    """A real lost push, through the dispatcher: the connection dies after the
    request went out, and nothing was created. The attempt records the marker its
    push carried, so "absent" can be trusted for it: once long enough has passed
    that the request cannot still land, it is pushed once -- never held for ever
    as an earlier release's push would be -- and never twice."""
    from assurance.markers import MARKER_VERSION

    admin = _admin()
    dep = _owed_pause(admin, connector_name)
    finding = Finding.objects.get(deployment=dep)
    remote = FakeRemote()
    real_post = remote.post

    def lost(url, *, headers, json):
        raise ConnectionResetError("the connection died before the answer; nothing was created")

    remote.post = lost
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    attempt = DispatchAttempt.objects.get(deployment=dep)
    assert attempt.outcome == DispatchAttempt.Outcome.UNKNOWN
    assert (attempt.marker, attempt.marker_version) == (_ours(finding, connector_name).text, MARKER_VERSION)
    remote.post = real_post
    # Not yet: a request the transport stopped waiting for may still land.
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.OWED
    assert remote.creates == 0
    DispatchAttempt.objects.filter(pk=attempt.pk).update(
        updated_at=timezone.now() - timedelta(seconds=dispatch.CLAIM_SECONDS + 1)
    )
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    attempt.refresh_from_db()
    assert attempt.outcome == DispatchAttempt.Outcome.SENT and "held" not in attempt.detail
    assert remote.creates == 1
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory) == dispatch.SETTLED
    assert remote.creates == 1 and remote.for_finding(finding) == [attempt.external_ref]


# ------------------------------------------------------ a halted push is undone


@with_key
def test_a_halted_push_restores_the_attempt_it_found():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1, severity="low")
    _opted_in(dep, min_severity="low")
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    down = HeldConnector(status=503)
    down.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=down.factory) == dispatch.OWED
    before = DispatchAttempt.objects.values("outcome", "attempts", "detail").get(deployment=dep)

    class LiftedDuringTheLook(FakeRemote):
        def get(self, url, *, headers, params=None):
            recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False)
            return super().get(url, headers=headers, params=params)

    remote = LiftedDuringTheLook()
    dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=remote.factory)
    assert remote.creates == 0
    assert DispatchAttempt.objects.values("outcome", "attempts", "detail").get(deployment=dep) == before


# --------------------------------------------------- no logging on a stop's path


@with_key
def test_a_stop_never_waits_on_a_slow_log_sink(django_capture_on_commit_callbacks, monkeypatch):
    """Past the bound, with a log sink that takes 2 s a record: the stop answers
    at once. It logs nothing itself; the sweep reports what was not started."""
    import logging as _logging

    class Slow(_logging.Handler):
        def emit(self, record):
            time.sleep(2.0)

    released = threading.Event()
    monkeypatch.setattr(
        dispatch, "run_blocking_decision_dispatch", lambda pk, **kw: released.wait(HOLD) and dispatch.SETTLED
    )
    admin = _admin()
    client = _client(admin)
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    _warm(client, dep)
    monkeypatch.setattr(dispatch, "_NOT_STARTED", [0])
    sink = Slow()
    log = _logging.getLogger("assurance")
    log.addHandler(sink)
    try:
        with override_settings(ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS=1, ASSURANCE_DISPATCH_MAX_WAITING_RUNS=0):
            assert dispatch.start_blocking_decision_dispatch(5151) == dispatch.STARTED
            began = time.monotonic()
            with django_capture_on_commit_callbacks(execute=True):
                assert _paused_via_route(client, dep).status_code == 200
            took = time.monotonic() - began
            assert took < 0.1, took
            assert dispatch._NOT_STARTED[0] == 1
            # And a stop whose record fails, which logs at ERROR: from another thread.
            other = _scanned(admin)
            _findings(other, count=1)
            _opted_in(other)

            def broken(**kwargs):
                raise DatabaseError("disk I/O error")

            monkeypatch.setattr(DecisionDispatchDue.objects, "create", broken)
            began = time.monotonic()
            with django_capture_on_commit_callbacks(execute=True):
                assert _paused_via_route(client, other).status_code == 200
            took = time.monotonic() - began
            assert took < 0.1, took
    finally:
        log.removeHandler(sink)
        released.set()
        _settle()


# ------------------------------------------------ sweepers in many processes


def test_a_sweep_claims_what_it_starts_so_other_processes_start_other_rows(monkeypatch, caplog):
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    deps = [_scanned(admin) for _ in range(6)]
    now = timezone.now()
    for n, dep in enumerate(deps):
        DecisionDispatchDue.objects.create(deployment=dep, owed_since=now - timedelta(minutes=10 - n))
    with override_settings(ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS=1, ASSURANCE_DISPATCH_MAX_WAITING_RUNS=1):
        monkeypatch.setattr(dispatch, "_JOBS", {})

        def fill(pk, **kwargs):
            started(pk, **kwargs)
            dispatch._JOBS[pk] = False
            return dispatch.STARTED

        monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", fill)
        with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
            caplog.clear()
            first = dispatch.sweep_owed_blocking_dispatches()
            # One summary line for the sweep, not one per row.
            assert caplog.text.count("left for the next") == 1
        # "Another process": its own jobs; the rows the first one claimed are live claims.
        monkeypatch.setattr(dispatch, "_JOBS", {})
        second = dispatch.sweep_owed_blocking_dispatches()
    assert first == [deps[0].pk, deps[1].pk]
    assert second == [deps[2].pk, deps[3].pk]
    tokens = dict(DecisionDispatchDue.objects.values_list("deployment_id", "run_token"))
    assert all(tokens[pk] for pk in first + second) and not tokens[deps[5].pk]
    assert [kw.get("token") for kw in started.kwargs] == [tokens[pk] for pk in first + second]


def test_a_sweep_that_could_not_start_a_claimed_row_lets_it_go(monkeypatch):
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", lambda pk, **kw: dispatch.COALESCED)
    admin = _admin()
    dep = _scanned(admin)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now())
    assert dispatch.sweep_owed_blocking_dispatches() == []
    assert DecisionDispatchDue.objects.get(deployment=dep).run_token == ""


# ---------------------------------------------------------- rolling back 0042


@with_key
def test_migrating_back_past_0042_is_refused_while_an_attempt_is_sending():
    import importlib

    from django.apps import apps

    guard = importlib.import_module("assurance.migrations.0042_dispatch_attempt_sending")._no_sending_attempts
    guard(apps, None)  # nothing SENDING: allowed
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    finding = Finding.objects.get(deployment=dep)
    DispatchAttempt.objects.create(
        deployment=dep, finding=finding, connector="jira", outcome=DispatchAttempt.Outcome.SENDING,
        trigger=DispatchAttempt.Trigger.BLOCKING_DECISION,
    )
    with pytest.raises(RuntimeError, match="would push them again blind"):
        guard(apps, None)


# ------------------------------------------------------- the reconcile command


@with_key
def test_the_reconcile_command_is_strict_attributed_and_never_overwrites_a_settled_attempt(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    finding = Finding.objects.get(deployment=dep)
    attempt = DispatchAttempt.objects.create(
        deployment=dep, finding=finding, connector="splunk", outcome=DispatchAttempt.Outcome.UNKNOWN,
        trigger=DispatchAttempt.Trigger.BLOCKING_DECISION,
    )
    cmd = "reconcile_dispatch_attempt"
    with pytest.raises(CommandError, match="not an attempt uuid"):
        call_command(cmd, "nope", "--provider-has-it", "--by", "ops", stdout=io.StringIO())
    with pytest.raises(CommandError, match="cannot go with --provider-lacks-it"):
        call_command(cmd, str(attempt.uuid), "--provider-lacks-it", "--external-ref", "X", "--by", "ops")
    with pytest.raises(CommandError):
        call_command(cmd, str(attempt.uuid), "--provider-has-it", "--by", " ")
    # A runner settles it while the command runs: the command changes nothing.
    real = DispatchAttempt.objects.filter

    def settled_meanwhile(*args, **kwargs):
        if "reconciled_at__isnull" in kwargs:
            DispatchAttempt.objects.all().filter(pk=attempt.pk).update(outcome=DispatchAttempt.Outcome.SENT)
        return real(*args, **kwargs)

    monkeypatch.setattr(DispatchAttempt.objects, "filter", settled_meanwhile)
    with pytest.raises(CommandError, match="changed while this ran"):
        call_command(cmd, str(attempt.uuid), "--provider-lacks-it", "--by", "ops", stdout=io.StringIO())
    monkeypatch.undo()
    assert DispatchAttempt.objects.get(pk=attempt.pk).outcome == DispatchAttempt.Outcome.SENT
    with pytest.raises(CommandError, match="not uncertain"):
        call_command(cmd, str(attempt.uuid), "--provider-has-it", "--by", "ops", stdout=io.StringIO())
    DispatchAttempt.objects.filter(pk=attempt.pk).update(outcome=DispatchAttempt.Outcome.UNKNOWN)
    out = io.StringIO()
    call_command(cmd, str(attempt.uuid), "--provider-has-it", "--external-ref", "EVT-1", "--by", "ops", stdout=out)
    attempt.refresh_from_db()
    assert (attempt.outcome, attempt.external_ref) == (DispatchAttempt.Outcome.SENT, "EVT-1")
    assert attempt.reconciled_detail.startswith("operator-attested by ops")


@with_key
def test_a_sending_record_and_the_clearing_of_a_reconciliation_are_one_write():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    finding = Finding.objects.get(deployment=dep)
    DispatchAttempt.objects.create(
        deployment=dep, finding=finding, connector="jira", outcome=DispatchAttempt.Outcome.FAILED,
        trigger=DispatchAttempt.Trigger.BLOCKING_DECISION, reconciled_at=timezone.now(), reconciled_detail="absent",
    )
    binding = ConnectorBinding.objects.get(deployment=dep)
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    with CaptureQueriesContext(connection) as queries:
        row = dispatch._record(
            finding, binding, trigger=DispatchAttempt.Trigger.BLOCKING_DECISION,
            outcome=DispatchAttempt.Outcome.SENDING, detail="sending",
        )
    writes = [q["sql"] for q in queries.captured_queries if q["sql"].startswith("UPDATE")]
    assert len(writes) == 1 and "reconciled_at" in writes[0]
    row.refresh_from_db()
    assert row.reconciled_at is None and row.is_uncertain


# ============================================================ round 4

# ------------------------------------------------------------------- settings


_NEW_SETTINGS = {
    "ASSURANCE_INSTALLATION_ID": ("prod-eu-1", "prod-eu-1"),
    "ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS": ("7", 7),
    "ASSURANCE_DISPATCH_MAX_WAITING_RUNS": ("9", 9),
    "ASSURANCE_DISPATCH_SWEEP_SECONDS": ("45", 45.0),
    "ASSURANCE_CONNECTOR_DEADLINE_SECONDS": ("12.5", 12.5),
}


def _settings_module_under(monkeypatch, env):
    """``config/settings.py`` executed afresh with ``env`` in the environment."""
    import importlib.util
    from pathlib import Path

    for name in _NEW_SETTINGS:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("DJANGO_SECRET_KEY", os.environ.get("DJANGO_SECRET_KEY") or "x")
    path = Path(__file__).resolve().parent.parent / "config" / "settings.py"
    spec = importlib.util.spec_from_file_location("_settings_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", sorted(_NEW_SETTINGS))
def test_every_setting_this_change_adds_is_read_from_the_environment(monkeypatch, name):
    raw, expected = _NEW_SETTINGS[name]
    assert getattr(_settings_module_under(monkeypatch, {name: raw}), name) == expected
    unset = getattr(_settings_module_under(monkeypatch, {}), name)
    assert unset == {"ASSURANCE_INSTALLATION_ID": ""}.get(name, unset) and unset != expected


def test_a_setting_that_is_not_a_number_is_an_error_at_start_logged_once_and_the_default_used(monkeypatch, caplog):
    from assurance.checks import dispatch_settings

    module = _settings_module_under(monkeypatch, {"ASSURANCE_DISPATCH_SWEEP_SECONDS": "5m"})
    assert module.ASSURANCE_DISPATCH_SWEEP_SECONDS == "5m", "kept as given, for the check to name"
    monkeypatch.setattr(dispatch, "_SETTINGS_READ", {})
    with override_settings(ASSURANCE_DISPATCH_SWEEP_SECONDS="5m"):
        [error] = dispatch_settings()
        assert error.id == "assurance.E303" and "ASSURANCE_DISPATCH_SWEEP_SECONDS='5m' is not a number" in error.msg
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            dispatch.read_settings()  # at start
            # ... and never again, however often it is read.
            assert [dispatch._sweep_interval() for _ in range(1000)] == [dispatch.DEFAULT_SWEEP_SECONDS] * 1000
            from assurance import oplog

            oplog.drain()
        assert caplog.text.count("is not a number") == 1
    assert dispatch_settings() == []


def test_the_line_an_operator_must_see_never_waits_behind_a_stalled_log_sink(monkeypatch, caplog):
    """A log sink has stalled: a thread is inside it and never comes out. The line
    is on stderr at once, and the call does not wait for the sink -- this thread
    never writes to a handler. The handlers get it from the log thread once the
    sink lets go."""
    import sys

    from assurance import oplog

    stall, inside = threading.Event(), threading.Event()

    class Stalled(logging.Handler):
        def emit(self, record):
            inside.set()
            stall.wait(30)

    err = _Stderr()
    sink = Stalled()
    logging.getLogger("assurance").addHandler(sink)
    stuck = threading.Thread(target=lambda: logging.getLogger("assurance.dispatch").error("into the stalled sink"))
    try:
        stuck.start()
        assert inside.wait(5)
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            monkeypatch.setattr(sys, "__stderr__", err)
            began = time.monotonic()
            oplog.emit_now(logging.ERROR, "run `manage.py retry_blocking_dispatches --deployment %s`", 8)
            took = time.monotonic() - began
            line = err.text()
            monkeypatch.undo()
            assert took < 0.5, took
            assert "--deployment 8" in line
            stall.set()
            assert _logged(caplog, "--deployment 8")
    finally:
        monkeypatch.undo()
        err.close()
        stall.set()
        stuck.join(5)
        logging.getLogger("assurance").removeHandler(sink)


# ------------------------------------------------------- the log thread's queue


def test_a_deferred_record_keeps_its_time_its_thread_its_logger_and_its_traceback(caplog):
    from assurance import oplog

    with caplog.at_level(logging.ERROR):
        try:
            raise DatabaseError("disk I/O error")
        except DatabaseError:
            before = time.time()
            oplog.log_later(logging.ERROR, "deployment %s: failed", 42, exc=True, logger_name="assurance.views")
        oplog.drain()
    [record] = [r for r in caplog.records if r.getMessage() == "deployment 42: failed"]
    assert record.name == "assurance.views"
    assert record.threadName == threading.current_thread().name
    assert before <= record.created <= time.time()
    assert "DatabaseError: disk I/O error" in (record.exc_text or "")
    assert record.exc_info is None, "a frame kept alive in the queue"


def test_the_log_queue_is_bounded_drops_the_oldest_and_says_how_many(monkeypatch, caplog):
    from assurance import oplog

    stalled, entered = threading.Event(), threading.Event()

    class Stalled(logging.Handler):
        def emit(self, record):
            if record.getMessage() == "stall":
                entered.set()
                stalled.wait(10)

    sink = Stalled()
    logging.getLogger("assurance").addHandler(sink)
    monkeypatch.setattr(oplog, "MAX_QUEUED", 10)
    try:
        with caplog.at_level(logging.INFO):
            oplog.log_later(logging.WARNING, "stall")
            assert entered.wait(5), "the pump never took the record"
            for n in range(25):
                oplog.log_later(logging.WARNING, "noise %d", n)
            assert oplog.queued() == 10 and oplog.dropped() == 15
            stalled.set()
            assert oplog.drain() == 0
    finally:
        stalled.set()
        logging.getLogger("assurance").removeHandler(sink)
    messages = [r.getMessage() for r in caplog.records]
    assert [m for m in messages if m.startswith("noise")] == [f"noise {n}" for n in range(15, 25)]
    assert any("15 deferred log record(s) were dropped" in m for m in messages)


def test_what_is_still_queued_is_written_when_the_process_exits(monkeypatch, caplog):
    """No pump (it could not start): the exit writes the queue itself, bounded."""
    from assurance import oplog

    monkeypatch.setattr(oplog, "start_pump", lambda: False)
    monkeypatch.setattr(oplog, "_PUMP", [])
    with caplog.at_level(logging.WARNING):
        for n in range(3):
            oplog.log_later(logging.WARNING, "left at exit %d", n)
        assert oplog.queued() == 3
        oplog._flush_at_exit()
    assert oplog.queued() == 0
    assert [r.getMessage() for r in caplog.records if "left at exit" in r.getMessage()] == [
        f"left at exit {n}" for n in range(3)
    ]


def test_a_row_behind_its_log_is_reported_without_holding_the_lock_on_a_slow_sink(caplog):
    """The repair of a row behind its transition log was logged at ERROR inside
    the transaction holding the row lock -- a stop's among them: a 2 s log sink
    held that stop, and every writer behind it, for 2 s. Now it is reported from
    the log thread."""
    from assurance import oplog, revision

    class Slow(logging.Handler):
        def emit(self, record):
            time.sleep(2.0)

    admin = _admin()
    dep = _scanned(admin)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False)
    Deployment.objects.filter(pk=dep.pk).update(decision_revision=1)
    sink = Slow(level=logging.ERROR)
    logging.getLogger("assurance.revision").addHandler(sink)
    try:
        with caplog.at_level(logging.ERROR):
            with transaction.atomic():
                locked = Deployment.objects.select_for_update().get(pk=dep.pk)
                began = time.monotonic()
                revision.decision_in_force(locked)
                took = time.monotonic() - began
            oplog.drain(10)
    finally:
        logging.getLogger("assurance.revision").removeHandler(sink)
    assert took < 0.5, took
    assert "behind its transition log" in caplog.text


# ----------------------------------------------------------- the sweeper's start


def test_a_sweeper_that_could_not_start_is_started_again_after_a_backoff(monkeypatch, caplog):
    from assurance import oplog

    stop = threading.Event()
    monkeypatch.setattr(dispatch, "_SWEEPER", [])
    monkeypatch.setattr(dispatch, "_SWEEPER_RETRY", {})
    monkeypatch.setattr(dispatch, "_SWEEP_STOP", stop)
    monkeypatch.setattr(dispatch, "_sweeper", lambda interval, event: event.wait(30))
    real_start = threading.Thread.start
    refused = []

    def start(self):
        if self.name == dispatch.SWEEPER_THREAD and not refused:
            refused.append(1)
            raise RuntimeError("can't start new thread")
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    try:
        with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
            for _ in range(100):
                dispatch.ensure_owed_sweeper()
            oplog.drain()
            assert caplog.text.count("could not start the sweeper") == 1, "logged on every request"
            assert not (dispatch._SWEEPER and dispatch._SWEEPER[0][1].is_alive())
            # The backoff passes: the next request starts it.
            dispatch._SWEEPER_RETRY["next"] = 0.0
            dispatch.ensure_owed_sweeper()
            pid, thread = dispatch._SWEEPER[0]
            assert pid == os.getpid() and thread.is_alive() and thread.name == dispatch.SWEEPER_THREAD
            # And the log thread with it, before any shortage of threads.
            assert oplog._PUMP and oplog._PUMP[0][1].is_alive()
    finally:
        stop.set()
        for _pid, thread in dispatch._SWEEPER:
            if thread is not None and thread.is_alive():
                thread.join(5)


def test_the_first_request_starts_the_sweeper_and_one_that_died_is_started_again(monkeypatch):
    stop = threading.Event()
    monkeypatch.setattr(dispatch, "_SWEEPER", [])
    monkeypatch.setattr(dispatch, "_SWEEPER_RETRY", {})
    monkeypatch.setattr(dispatch, "_SWEEP_STOP", stop)
    lives = []

    def sweeper(interval, event):
        lives.append(1)
        if len(lives) == 1:
            return  # dies at once
        event.wait(30)

    monkeypatch.setattr(dispatch, "_sweeper", sweeper)
    try:
        dispatch.ensure_owed_sweeper()
        first = dispatch._SWEEPER[0][1]
        first.join(5)
        dispatch.ensure_owed_sweeper()
        second = dispatch._SWEEPER[0][1]
        assert second is not first and second.is_alive() and len(lives) == 2
    finally:
        stop.set()
        for _pid, thread in dispatch._SWEEPER:
            if thread is not None:
                thread.join(5)


def test_requests_arriving_together_start_one_sweeper(monkeypatch):
    """Four first requests at once, on an interpreter slow to start a thread: one
    sweeper is started, not one each."""
    stop = threading.Event()
    monkeypatch.setattr(dispatch, "_SWEEPER", [])
    monkeypatch.setattr(dispatch, "_SWEEPER_RETRY", {})
    monkeypatch.setattr(dispatch, "_SWEEP_STOP", stop)
    monkeypatch.setattr(dispatch, "_sweeper", lambda interval, event: event.wait(30))
    real_start = threading.Thread.start
    started = []

    def slow_start(self):
        if self.name == dispatch.SWEEPER_THREAD:
            started.append(self)
            time.sleep(0.05)
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", slow_start)
    go = threading.Event()
    callers = [threading.Thread(target=lambda: go.wait(5) and dispatch.ensure_owed_sweeper()) for _ in range(4)]
    try:
        for caller in callers:
            real_start(caller)
        go.set()
        for caller in callers:
            caller.join(5)
        assert len(started) == 1, f"{len(started)} sweepers started"
        dispatch.ensure_owed_sweeper()
        assert len(started) == 1 and dispatch._SWEEPER[0][1].is_alive()
    finally:
        stop.set()
        for thread in started:
            thread.join(5)


# ------------------------------------------ unrecorded dispatches: a hard bound


@with_key
def test_unrecorded_dispatches_have_a_hard_bound_and_past_it_each_is_named_at_once(monkeypatch, caplog):
    """The owed table cannot be read (the code deployed ahead of its migration):
    every stop is unrecorded. Their threads are started past the bound on waiting
    runs, but never past twice it; each one past that is named at ERROR, in the
    stop's own thread, on stderr, at once -- and in the log, from the log thread."""
    import sys

    released = threading.Event()
    monkeypatch.setattr(dispatch, "_blocking_dispatch_job", lambda pk, **kw: released.wait(HOLD))
    monkeypatch.setattr(dispatch, "_JOBS", {})
    err = _Stderr()
    try:
        with override_settings(ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS=1, ASSURANCE_DISPATCH_MAX_WAITING_RUNS=1):
            outcomes = [dispatch.start_blocking_decision_dispatch(6000 + n, unrecorded=True) for n in range(6)]
            with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
                monkeypatch.setattr(sys, "__stderr__", err)
                assert dispatch.start_blocking_decision_dispatch(6006, unrecorded=True) == dispatch.FULL
                # On stderr before the call returned.
                assert "retry_blocking_dispatches --deployment 6006" in err.text()
                monkeypatch.setattr(sys, "__stderr__", sys.stderr)
                assert _logged(caplog, "retry_blocking_dispatches --deployment 6006")
        assert outcomes == [dispatch.STARTED] * 4 + [dispatch.FULL] * 2
        assert len(dispatch._JOBS) == 4
    finally:
        err.close()
        released.set()
        _settle()


# ---------------------------------------------------------- the sweep, end to end


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_swept_row_is_run_by_the_thread_the_sweep_starts_under_the_sweeps_claim():
    """A process exited before its thread ran. The sweep claims the row and starts
    a thread that runs it under that claim: pushed once, and settled."""
    admin = _admin()
    dep = _owed_pause(admin)
    assert DecisionDispatchDue.objects.filter(deployment=dep).exists()
    remote = FakeRemote()
    dispatch_factory = dispatch._default_transport_factory
    dispatch._default_transport_factory = remote.factory
    try:
        assert dispatch.sweep_owed_blocking_dispatches() == [dep.pk]
        _settle()
    finally:
        dispatch._default_transport_factory = dispatch_factory
    assert remote.creates == 1
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists(), "the swept row was never run"
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.SENT


def test_a_sweep_leaves_a_claim_another_runner_took_after_it_read_the_row(monkeypatch):
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    dep = _scanned(admin)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now())
    real = dispatch._owed_row

    def raced(deployment_id):
        # Another process's runner claims it between this sweep's read and its claim.
        real(deployment_id).update(running_until=timezone.now() + timedelta(minutes=5), run_token="other")
        return real(deployment_id)

    monkeypatch.setattr(dispatch, "_owed_row", raced)
    assert dispatch.sweep_owed_blocking_dispatches() == []
    assert started == []
    assert DecisionDispatchDue.objects.get(deployment=dep).run_token == "other"


def test_a_sweep_leaves_a_row_this_process_is_already_running(monkeypatch):
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    admin = _admin()
    dep = _scanned(admin)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now())
    monkeypatch.setattr(dispatch, "_JOBS", {dep.pk: False})  # its thread waits for a slot
    assert dispatch.sweep_owed_blocking_dispatches() == []
    assert started == [] and dispatch._JOBS == {dep.pk: False}
    assert DecisionDispatchDue.objects.get(deployment=dep).run_token == ""


def test_a_sweep_reports_the_stops_it_could_not_start_once(monkeypatch, caplog):
    monkeypatch.setattr(dispatch, "_NOT_STARTED", [3])
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        dispatch.sweep_owed_blocking_dispatches()
        dispatch.sweep_owed_blocking_dispatches()
    assert caplog.text.count("3 not started by stops since the last sweep") == 1
    assert dispatch._NOT_STARTED == [0]


def test_rows_other_runners_hold_never_fill_a_sweeps_batch(monkeypatch):
    """A sweep reads a batch of rows at a time. Rows another runner holds are not
    read into it, so they can never crowd out one that is due."""
    started = _Calls()
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started)
    monkeypatch.setattr(dispatch, "_SWEEP_BATCH", 1)
    admin = _admin()
    held, due = _scanned(admin), _scanned(admin)
    now = timezone.now()
    DecisionDispatchDue.objects.create(
        deployment=held, owed_since=now - timedelta(hours=1), running_until=now + timedelta(minutes=5), run_token="x"
    )
    DecisionDispatchDue.objects.create(deployment=due, owed_since=now)
    assert dispatch.sweep_owed_blocking_dispatches() == [due.pk]


# ------------------------------------------------------------ rolling back 0043


@with_key
def test_migrating_back_past_0043_is_refused_while_an_uncertain_attempt_carries_a_marker():
    import importlib

    from django.apps import apps

    back = importlib.import_module("assurance.migrations.0043_dispatch_markers")._back_to_0042
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    closed = _lost(dep, outcome=DispatchAttempt.Outcome.SENT_TO_CLOSED)
    back(apps, None)
    closed.refresh_from_db()
    assert closed.outcome == DispatchAttempt.Outcome.SENT, "code before 0043 knows it as sent"
    DispatchAttempt.objects.filter(pk=closed.pk).update(outcome=DispatchAttempt.Outcome.UNKNOWN)
    with pytest.raises(RuntimeError, match="cannot look for"):
        back(apps, None)


@pytest.mark.django_db(transaction=True)
def test_0043_adds_the_marker_without_copying_the_table_and_older_code_can_still_insert():
    """0043 adds ``marker`` nullable, with no default: a plain ADD COLUMN, not a
    copy of the table (which holds the write lock for as long as the copy takes).
    Code still serving from before it -- a rolling deploy, migrate then restart --
    inserts attempts without the column; each is read as an earlier release's."""
    from django.db import connection

    out = io.StringIO()
    call_command("sqlmigrate", "assurance", "0043", stdout=out)
    sql = out.getvalue()
    assert "new__assurance_dispatchattempt" not in sql, "0043 copies the attempts table"
    assert 'ALTER TABLE "assurance_dispatchattempt" ADD COLUMN "marker" varchar(128) NULL' in sql
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    finding = Finding.objects.get(deployment=dep)
    now = timezone.now()
    with connection.cursor() as cursor:
        # The columns code before 0043 writes, and no others.
        cursor.execute(
            "INSERT INTO assurance_dispatchattempt (uuid, deployment_id, finding_id, binding_id, connector, outcome, "
            "trigger, detail, external_ref, operation_id, policy_epoch, reconciled_at, reconciled_detail, attempts, "
            "created_at, updated_at) VALUES (%s, %s, %s, NULL, 'jira', 'unknown', 'manual', '', '', 'op', 'paused', "
            "NULL, '', 1, %s, %s)",
            [uuid.uuid4().hex, dep.pk, finding.pk, now, now],
        )
    attempt = DispatchAttempt.objects.get(finding=finding)
    assert attempt.marker is None and attempt.marker_version is None and attempt.is_uncertain
