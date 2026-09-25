"""A row behind its transition log is published as the log records it.

The transition log is what every consumer draining ``transitions_since`` was told.
A Deployment row whose ``decision_revision`` is below the log's latest revision --
legacy data only: the stale full save before ``Deployment.save`` stopped writing the
decision columns, or ``loaddata`` of a fixture dumped before its log moved -- was
repaired only inside ``recompute_decision``. Until something recomputed that
deployment, every surface published the stale row: the operator paused at revision
2, the log said PAUSED at 2, and the detail, the list, decision-support (with
``paused: false``), ``read_decision``, the receipt and the dispatch fence all said
READY at 1. A consumer that had acted on the pause and fenced its next read at
revision 2 was refused with ``StaleDecisionRead`` for as long as nothing came by.

Three defences, each pinned here:

- every read publishes the decision IN FORCE -- the log's, when the row is behind
  it -- and never the READY beneath a logged pause, even where the row cannot be
  written;
- ``current_decision`` repairs the row it publishes, through the one writer
  (``accept_transition``, the no-op move to what the log records), and
  ``decision_support`` -- a read that persists nothing -- repairs nothing;
- ``post_migrate`` brings every row behind its log level at the upgrade.

And nothing a read adds stands between an operator and a pause.
"""

from __future__ import annotations

import logging

import pytest
from django.apps import apps as live_apps
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import OperationalError, connection
from django.db.migrations.state import ProjectState
from django.db.models import QuerySet
from django.test import Client, RequestFactory
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import revision, signals, views
from assurance.admin import DeploymentAdmin
from assurance.decision import current_decision, decision_support, recompute_decision
from assurance.dispatch import policy_epoch
from assurance.models import DecisionTransition, Deployment, Finding
from assurance.revision import (
    StaleDecisionRead,
    accept_transition,
    in_force_of,
    logged_head,
    read_decision,
    transitions_since,
)

pytestmark = pytest.mark.django_db

User = get_user_model()
D = Deployment.Decision


def _owner():
    return User.objects.create_user(
        username=f"o{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _client(dep):
    client = APIClient()
    client.force_authenticate(user=dep.owner)
    client.raise_request_exception = False
    return client


def _scanned_ready():
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_owner())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    recompute_decision(dep)
    assert dep.decision == D.READY
    return dep


def _log(dep):
    return list(
        DecisionTransition.objects.filter(deployment=dep)
        .order_by("revision")
        .values_list("revision", "from_decision", "to_decision")
    )


def _row(dep):
    return Deployment.objects.values_list("decision", "decision_revision").get(pk=dep.pk)


def _paused_beneath_its_log():
    """READY at 1, paused through the route at 2 -- and the row written back to
    READY at 1 beneath the log, the wedge the stale save left. Planted with a
    QuerySet update, which the model cannot see. A medium finding is recorded
    first so the incident pack has a finding to be read through."""
    dep = _scanned_ready()
    Finding.objects.create(
        deployment=dep, fingerprint="fp", finding_type="t", title="T", severity="medium"
    )
    response = _client(dep).post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
    )
    assert response.status_code == 200 and response.json()["decision"] == D.PAUSED
    assert _log(dep)[-1] == (2, D.READY, D.PAUSED)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=1)
    assert _row(dep) == (D.READY, 1)
    return dep


def _bare_pause_beneath_its_log():
    """The same wedge with no finding, paused by a recompute: for a transactional
    test, where a finding's after-commit refresh would move the decision first."""
    dep = _scanned_ready()
    recompute_decision(dep, paused=True)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=1)
    assert _log(dep) == [(1, "", D.READY), (2, D.READY, D.PAUSED)]
    return dep


def _errors(caplog):
    return [r for r in caplog.records if r.levelno >= logging.ERROR]


# ---------------------------------------------------------------------------
# Every surface, read FIRST on a row behind its log
# ---------------------------------------------------------------------------
#
# Each returns (decision, revision) -- revision None where the surface publishes
# none -- and is the first read of the wedged row, so what it publishes is its own
# doing and not an earlier surface's repair.


def _base(dep):
    return f"/api/assurance/deployments/{dep.uuid}/"


def _detail(dep):
    body = _client(dep).get(_base(dep)).json()
    assert body["decision_label"] == D.PAUSED.label, body
    return body["decision"], body["decision_revision"]


def _list(dep):
    body = _client(dep).get("/api/assurance/deployments/").json()
    rows = body["results"] if isinstance(body, dict) else body
    row = next(row for row in rows if row["uuid"] == str(dep.uuid))
    return row["decision"], row["decision_revision"]


def _decision_support_route(dep):
    body = _client(dep).get(_base(dep) + "decision-support/").json()
    assert body["paused"] is True, body
    return body["decision"], body["revision"]


def _read_decision(dep):
    # Fenced at the revision the log published the pause under: the consumer that
    # acted on it asks for nothing older, and is not refused.
    read = read_decision(dep, at_least=2)
    return read["decision"], read["revision"]


def _receipt(dep):
    body = _client(dep).get(_base(dep) + "assurance-receipt/").json()
    return body["result"]["decision"], None


def _bundle(dep):
    body = _client(dep).post("/api/assurance/deployments/check/", {}, format="json").json()
    [row] = [row for row in body["decisions"] if row["subject"] == dep.name]
    return row["state"], None


def _executive_summary(dep):
    return _client(dep).get(_base(dep) + "executive-summary/").json()["decision"]["decision"], None


def _operational_assurance(dep):
    body = _client(dep).get(_base(dep) + "operational-assurance/").json()
    return body["decision"]["decision"], None


def _incident_pack(dep):
    finding = Finding.objects.get(deployment=dep)
    body = _client(dep).get(f"/api/assurance/findings/{finding.uuid}/incident-pack/").json()
    return body["decision"]["decision"], None


def _dispatch_fence(dep):
    # What `dispatch_finding` does before it compares epochs: reconcile the
    # deployment it holds, then read the epoch off it.
    held = Finding.objects.select_related("deployment").get(deployment=dep).deployment
    current_decision(held)
    return policy_epoch(held), held.decision_revision


_SURFACES = [
    _detail,
    _list,
    _decision_support_route,
    _read_decision,
    _receipt,
    _bundle,
    _executive_summary,
    _operational_assurance,
    _incident_pack,
    _dispatch_fence,
]


def _published(surface, dep):
    decision, published_revision = surface(dep)
    assert decision == D.PAUSED, (surface.__name__, decision)
    assert published_revision in (None, 2), (surface.__name__, published_revision)


@pytest.mark.parametrize("surface", _SURFACES, ids=lambda s: s.__name__.strip("_"))
def test_every_surface_publishes_the_pause_the_log_records_and_repairs_the_row(caplog, surface):
    """PAUSED at 2 on every surface, read first -- and the row brought up to its log
    by that read, through the one writer, with nothing new recorded: the pause was
    recorded when the operator made it. Reported once, at ERROR, naming it."""
    dep = _paused_beneath_its_log()
    log = _log(dep)

    with caplog.at_level(logging.ERROR):
        _published(surface, dep)

    assert _row(dep) == (D.PAUSED, 2), "the read repaired the row it published"
    assert _log(dep) == log, "a read records no transition"
    errors = _errors(caplog)
    assert len(errors) == 1, [r.getMessage() for r in errors]
    assert errors[0].name == "assurance.revision"
    assert f"deployment {dep.pk}:" in errors[0].getMessage()
    assert "behind its transition log" in errors[0].getMessage()
    # And every surface after it agrees, under the log's revision.
    for other in _SURFACES:
        _published(other, dep)


@pytest.mark.parametrize("surface", _SURFACES, ids=lambda s: s.__name__.strip("_"))
def test_a_read_that_cannot_repair_the_row_still_publishes_the_pause(caplog, monkeypatch, surface):
    """Where the row cannot be written -- a lock not granted in time, a read-only
    connection -- the read still publishes what the log records. It does not fail
    on the pause and it does not fall back to the stale row: a pause is never read
    as READY."""
    dep = _paused_beneath_its_log()

    def locked_out(*args, **kwargs):
        raise OperationalError("database is locked")

    monkeypatch.setattr(revision, "accept_transition", locked_out)
    with caplog.at_level(logging.ERROR):
        _published(surface, dep)

    assert _row(dep) == (D.READY, 1), "nothing could be written"
    assert any(
        "could not be brought up to it" in r.getMessage() and f"deployment {dep.pk}:" in r.getMessage()
        for r in _errors(caplog)
    ), [r.getMessage() for r in _errors(caplog)]


@pytest.mark.parametrize("surface", _SURFACES, ids=lambda s: s.__name__.strip("_"))
def test_a_repair_the_one_writer_refuses_still_publishes_the_pause(caplog, monkeypatch, surface):
    """``accept_transition`` refuses a reading of a row that has moved since it was
    read (``StaleDecisionRead``). A read that met the refusal raised it -- a 500 on
    a GET -- where it must publish what the log records, as it does when the row
    cannot be written: never the READY beneath the logged pause."""
    dep = _paused_beneath_its_log()
    reading = revision.decision_in_force

    def read_before_the_row_moved(locked):
        return reading(locked)._replace(read_from=(locked.pk, D.READY, 0))

    monkeypatch.setattr(revision, "decision_in_force", read_before_the_row_moved)
    with caplog.at_level(logging.ERROR):
        _published(surface, dep)

    assert _row(dep) == (D.READY, 1), "the refused move wrote nothing"
    refused = [r for r in _errors(caplog) if "could not be brought up to it" in r.getMessage()]
    assert refused and refused[0].exc_info[0] is StaleDecisionRead, [
        r.getMessage() for r in _errors(caplog)
    ]


@pytest.mark.django_db(transaction=True)
def test_a_read_repairs_the_row_from_a_reading_taken_under_its_lock_in_its_own_transaction(
    monkeypatch,
):
    """The decision in force the repair moves from is read under the row lock, in
    the transaction the move commits in. SQLite serialises writers itself, so
    neither shows here unless asked for; on PostgreSQL a GET runs in autocommit,
    where a row lock outside a transaction is refused (no read would ever repair a
    row), and a reading off an unlocked row can go stale before the one writer
    locks it, which refuses it. A transactional test: inside the test's own
    transaction every read is in an atomic block."""
    dep = _bare_pause_beneath_its_log()
    locked, readings = [], []
    lock = QuerySet.select_for_update
    reading = revision.decision_in_force

    def select_for_update(self, *args, **kwargs):
        locked.append(self.model)
        return lock(self, *args, **kwargs)

    def decision_in_force(row):
        readings.append((connection.in_atomic_block, list(locked)))
        return reading(row)

    monkeypatch.setattr(QuerySet, "select_for_update", select_for_update)
    monkeypatch.setattr(revision, "decision_in_force", decision_in_force)
    assert _detail(dep) == (D.PAUSED, 2)

    assert _row(dep) == (D.PAUSED, 2), "the read did not repair the row"
    in_a_transaction, locked_first = readings[0]
    assert in_a_transaction, "the decision in force was read outside a transaction"
    assert Deployment in locked_first, "the decision in force was read off an unlocked row"


def test_a_repair_that_fails_on_a_deployment_deleted_meanwhile_raises(monkeypatch):
    """The repair failed, and the fallback finds no row to read what is in force
    from: the instance held is stale and there is nothing current to publish, so
    the read fails -- it does not publish the instance as if nothing happened."""
    dep = _paused_beneath_its_log()
    held = Deployment.objects.annotate(**logged_head()).get(pk=dep.pk)
    Deployment.objects.filter(pk=dep.pk).delete()

    def locked_out(pk):
        raise OperationalError("database is locked")

    monkeypatch.setattr(revision, "bring_up_to_its_log", locked_out)
    with pytest.raises(OperationalError):
        current_decision(held)


def test_a_row_behind_its_log_on_the_decision_the_log_records_is_reported(caplog):
    """Behind is a matter of the revision, not of the decision: a row written back
    to READY at 1 beneath a log whose head is READY at 3 is as wedged as one
    beneath a pause, and is reported as the ERROR it is."""
    dep = _scanned_ready()
    recompute_decision(dep, paused=True)
    recompute_decision(dep, paused=False)
    assert _log(dep)[-1] == (3, D.PAUSED, D.READY)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=1)

    with caplog.at_level(logging.ERROR):
        in_force = revision.decision_in_force(Deployment.objects.get(pk=dep.pk))

    assert (in_force.decision, in_force.revision) == (D.READY, 3)
    [error] = _errors(caplog)
    assert "behind its transition log" in error.getMessage()


@pytest.mark.django_db(transaction=True)
def test_decision_support_reads_its_parts_and_its_pause_in_one_transaction(monkeypatch):
    """The parts and the pause and revision published beside them are one moment
    only inside one transaction. Inside the test's own transaction every read is;
    a real request runs in autocommit, so this is a transactional test."""
    from assurance import decision as decision_module

    dep = _bare_pause_beneath_its_log()
    seen = []
    parts = decision_module.read_decision_parts
    published = revision.published_decision

    def read_parts(*args, **kwargs):
        seen.append(("parts", connection.in_atomic_block))
        return parts(*args, **kwargs)

    def read_published(pk):
        seen.append(("published", connection.in_atomic_block))
        return published(pk)

    monkeypatch.setattr(decision_module, "read_decision_parts", read_parts)
    monkeypatch.setattr(revision, "published_decision", read_published)

    support = decision_support(Deployment.objects.get(pk=dep.pk))

    assert (support["decision"], support["revision"], support["paused"]) == (D.PAUSED, 2, True)
    assert seen == [("parts", True), ("published", True)], seen


def test_a_consumer_fenced_at_the_logged_pause_is_not_refused():
    """The reproducer's end state: told PAUSED at revision 2 by the log, the
    consumer fenced its next read there and got StaleDecisionRead for good."""
    dep = _paused_beneath_its_log()
    assert [(t.revision, t.to_decision) for t in transitions_since(dep, 0)][-1] == (2, D.PAUSED)

    assert read_decision(dep, at_least=2) == {"decision": D.PAUSED, "revision": 2}
    with pytest.raises(StaleDecisionRead):
        read_decision(dep, at_least=3)


def test_decision_support_reads_the_pause_the_log_records_and_writes_nothing():
    """The function, not the route: a read that persists nothing. It publishes the
    decision in force and leaves the repair to ``current_decision``."""
    dep = _paused_beneath_its_log()
    log = _log(dep)

    support = decision_support(Deployment.objects.get(pk=dep.pk))

    assert (support["decision"], support["revision"], support["paused"]) == (D.PAUSED, 2, True)
    assert _row(dep) == (D.READY, 1)
    assert _log(dep) == log


def test_a_row_behind_a_log_that_moved_off_the_pause_is_published_as_the_lift():
    """The mirror: a stale PAUSED written back beneath a logged lift is not
    published as a pause the operator already released."""
    dep = _scanned_ready()
    recompute_decision(dep, paused=True)
    recompute_decision(dep, paused=False)
    assert _log(dep)[-1] == (3, D.PAUSED, D.READY)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.PAUSED, decision_revision=2)

    assert read_decision(dep, at_least=3) == {"decision": D.READY, "revision": 3}
    assert decision_support(dep)["paused"] is False
    assert _row(dep) == (D.READY, 3)


def test_a_row_level_with_or_ahead_of_its_log_is_published_as_it_stands(caplog):
    """A row with a revision and no transitions behind it (decided before the log
    existed) is not behind anything; it is trusted, and nothing is written."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    accept_transition(dep, to_decision=D.PAUSED)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=5)

    with caplog.at_level(logging.ERROR):
        assert read_decision(dep) == {"decision": D.READY, "revision": 5}
        assert decision_support(dep)["revision"] == 5

    assert _log(dep) == [(1, "", D.PAUSED)]
    assert _errors(caplog) == []


def test_the_in_force_rule_reads_an_unassessed_log_head_as_no_decision():
    assert in_force_of(D.READY, 1, None, None) == (D.READY, 1)
    assert in_force_of(D.READY, 2, 2, D.PAUSED) == (D.READY, 2)
    assert in_force_of(D.READY, 1, 2, D.PAUSED) == (D.PAUSED, 2)
    assert in_force_of(D.READY, 1, 2, "") == (None, 2)


def test_the_admin_list_shows_the_pause_the_log_records_and_writes_nothing():
    """The changelist is a list of the stored rows; its decision column is the one
    in force, from the log head read in the list's own query."""
    dep = _paused_beneath_its_log()
    model_admin = DeploymentAdmin(Deployment, admin.site)
    request = RequestFactory().get("/admin/assurance/deployment/")
    request.user = dep.owner

    row = model_admin.get_queryset(request).get(pk=dep.pk)

    assert model_admin.decision_in_force(row) == D.PAUSED.label
    assert _row(dep) == (D.READY, 1)


def test_the_admin_change_form_shows_the_pause_the_log_records_and_writes_nothing():
    """The page an operator opens to check a pause shows the decision in force and
    its revision -- not the stored columns, which on a row behind its log hold the
    READY beneath the pause at revision 1. A read: it repairs nothing."""
    dep = _paused_beneath_its_log()
    web = Client()
    web.force_login(User.objects.create_superuser(username="root", password="x", email="r@x.io"))

    response = web.get(f"/admin/assurance/deployment/{dep.pk}/change/")

    assert response.status_code == 200
    shown = {
        field.field["name"]: field.contents()
        for fieldset in response.context["adminform"]
        for line in fieldset
        for field in line
        if field.is_readonly
    }
    assert (shown["decision_in_force"], shown["revision_in_force"]) == (D.PAUSED.label, "2")
    assert "decision" not in shown and "decision_revision" not in shown, shown
    assert _row(dep) == (D.READY, 1)
    # And the form for a new deployment, which has no log, still renders.
    assert web.get("/admin/assurance/deployment/add/").status_code == 200


# ---------------------------------------------------------------------------
# What asking costs
# ---------------------------------------------------------------------------


def _standalone_log_reads(queries):
    return [
        q["sql"]
        for q in queries.captured_queries
        if q["sql"].startswith('SELECT "assurance_decisiontransition"')
    ]


def test_the_list_and_the_bundle_ask_no_row_for_its_log_head_on_its_own():
    """The list and the bundle read each row's log head in their one query; asking
    per row would make their cost grow with the portfolio."""
    from assurance.bundle import assurance_bundle

    dep = _scanned_ready()
    for _ in range(4):
        _scanned_ready()
    client = _client(dep)
    with CaptureQueriesContext(connection) as listed:
        assert client.get("/api/assurance/deployments/").status_code == 200
    with CaptureQueriesContext(connection) as bundled:
        assurance_bundle(Deployment.objects.all())

    assert _standalone_log_reads(listed) == []
    assert _standalone_log_reads(bundled) == []


@pytest.mark.parametrize("route", ["executive-summary", "operational-assurance"])
def test_the_summaries_ask_no_row_for_its_log_head_on_its_own(route):
    """Each summary reads its deployment with the log head in the query it already
    makes: asking apart would cost a query, and read a moment the row was not."""
    dep = _scanned_ready()
    client = _client(dep)
    with CaptureQueriesContext(connection) as queries:
        assert client.get(_base(dep) + route + "/").status_code == 200

    assert _standalone_log_reads(queries) == []


def test_read_decision_reads_the_row_and_its_log_head_in_one_statement(
    django_assert_num_queries,
):
    """What ``logged_head`` is for: the row and the head of its log read as one
    moment -- read apart, a transition committed between them makes a current row
    look behind. One statement, and nothing else, for a row level with its log."""
    dep = _scanned_ready()

    with django_assert_num_queries(1) as queries:
        assert read_decision(dep) == {"decision": D.READY, "revision": 1}

    assert _standalone_log_reads(queries) == []


def test_an_instance_read_without_its_log_head_costs_one_query_to_hold_to_it(
    django_assert_num_queries,
):
    dep = _scanned_ready()
    plain = Deployment.objects.get(pk=dep.pk)

    with django_assert_num_queries(1):
        assert current_decision(plain) == D.READY
    with django_assert_num_queries(0):
        assert current_decision(plain) == D.READY, "asked once per instance"


# ---------------------------------------------------------------------------
# Nothing a read adds stands between an operator and a pause
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("paused", [True, False])
def test_the_pause_route_never_reads_the_log_head_the_reads_do(monkeypatch, paused):
    """The route that pauses and lifts loads its deployment without the log head:
    ``recompute_decision`` reads the decision in force under the row lock. A log
    head that could not be read fails every published read, and never a pause."""
    dep = _scanned_ready()
    if not paused:
        recompute_decision(dep, paused=True)

    def unreadable():
        raise OperationalError("the log head could not be read")

    monkeypatch.setattr(views, "logged_head", unreadable)
    response = _client(dep).post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": paused}, format="json"
    )

    assert response.status_code == 200, response.content
    expected = D.PAUSED if paused else D.READY
    assert response.json()["decision"] == expected
    assert _log(dep)[-1][2] == expected


def test_a_pause_on_a_row_behind_its_log_is_recorded_from_the_log():
    """The operator pauses a deployment whose row a stale save wrote back beneath
    a logged NOT_RECOMMENDED: the pause lands, FROM what the log records."""
    dep = _scanned_ready()
    accept_transition(dep, to_decision=D.NOT_RECOMMENDED)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=1)

    response = _client(dep).post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
    )

    assert response.status_code == 200 and response.json()["decision"] == D.PAUSED
    assert _log(dep)[-1] == (3, D.NOT_RECOMMENDED, D.PAUSED)
    assert read_decision(dep, at_least=3) == {"decision": D.PAUSED, "revision": 3}


# ---------------------------------------------------------------------------
# The upgrade brings every row behind its log level
# ---------------------------------------------------------------------------


def _assurance():
    return live_apps.get_app_config("assurance")


def _behind_on_a_critical_finding():
    """NOT_RECOMMENDED at 2 over an open critical finding, the row written back to
    READY at 1."""
    dep = _scanned_ready()
    Finding.objects.create(
        deployment=dep, fingerprint="fp", finding_type="t", title="T", severity="critical"
    )
    recompute_decision(dep)
    assert _log(dep)[-1] == (2, D.READY, D.NOT_RECOMMENDED)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=1)
    return dep


def test_the_upgrade_brings_every_row_behind_its_log_level_and_keeps_its_pause(caplog):
    paused = _paused_beneath_its_log()
    critical = _behind_on_a_critical_finding()
    level = _scanned_ready()
    ahead = _scanned_ready()
    Deployment.objects.filter(pk=ahead.pk).update(decision_revision=7)
    logs = {dep.pk: _log(dep) for dep in (paused, critical, level, ahead)}
    untouched = {dep.pk: _row(dep) for dep in (level, ahead)}

    with caplog.at_level(logging.ERROR):
        signals.repair_decisions_behind_their_log(sender=_assurance(), using="default")

    assert _row(paused) == (D.PAUSED, 2), "the pause the log records, not a lift"
    assert _row(critical) == (D.NOT_RECOMMENDED, 2)
    assert {dep.pk: _row(dep) for dep in (level, ahead)} == untouched
    assert {dep.pk: _log(dep) for dep in (paused, critical, level, ahead)} == logs
    reported = sorted(r.getMessage().split(":")[0] for r in _errors(caplog))
    assert reported == sorted([f"deployment {paused.pk}", f"deployment {critical.pk}"])

    # Idempotent: a second migrate finds nothing behind and moves nothing.
    caplog.clear()
    signals.repair_decisions_behind_their_log(sender=_assurance(), using="default")
    assert _row(paused) == (D.PAUSED, 2)
    assert _errors(caplog) == []


def _a_critical_finding_no_refresh_saw(dep):
    """An input moved with no refresh behind it: bulk_create sends no signal, so a
    recompute of ``dep`` WOULD move its decision now."""
    Finding.objects.bulk_create(
        [Finding(deployment=dep, fingerprint="fp", finding_type="t", title="T", severity="critical")]
    )


def test_the_upgrade_repair_decides_nothing(monkeypatch):
    """A migrate brings a row up to the decision its log records and computes
    none. It runs wherever the schema is upgraded, which need not be where the
    outcome keyring is installed; a recompute there recorded a decision computed
    without the keyring as the next transition. Here the keyring cannot be read and
    the inputs have moved: the row is brought to the READY its log records at 3,
    and nothing is recorded."""
    from assurance import decision as decision_module
    from assurance import observed_outcomes

    dep = _scanned_ready()
    recompute_decision(dep, paused=True)
    recompute_decision(dep, paused=False)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.PAUSED, decision_revision=2)
    _a_critical_finding_no_refresh_saw(dep)
    log = _log(dep)

    def decided(*args, **kwargs):
        raise AssertionError("the upgrade repair computed a decision")

    monkeypatch.setattr(observed_outcomes, "trusted_keyring", decided)
    monkeypatch.setattr(decision_module, "compute_decision", decided)
    signals.repair_decisions_behind_their_log(sender=_assurance(), using="default")

    assert _row(dep) == (D.READY, 3)
    assert _log(dep) == log


def test_an_unrelated_migrate_recomputes_no_row_level_with_its_log(django_assert_num_queries):
    """A row level with or ahead of its log, or with no log at all, is not touched
    -- not even locked: the one query that finds nothing behind is all a migrate
    costs, and a level row whose inputs moved without a refresh keeps the decision
    it holds."""
    level = _scanned_ready()
    _a_critical_finding_no_refresh_saw(level)
    ahead = _scanned_ready()
    Deployment.objects.filter(pk=ahead.pk).update(decision_revision=7)
    unlogged = Deployment.objects.create(name="unlogged", owner=_owner())
    deployments = (level, ahead, unlogged)
    rows = {dep.pk: _row(dep) for dep in deployments}
    logs = {dep.pk: _log(dep) for dep in deployments}

    with django_assert_num_queries(1):
        signals.repair_decisions_behind_their_log(
            sender=_assurance(), using="default", apps=live_apps
        )

    assert {dep.pk: _row(dep) for dep in deployments} == rows
    assert {dep.pk: _log(dep) for dep in deployments} == logs


def test_a_migrate_repairs_a_row_behind_its_log():
    """End to end, as an upgrade runs it: ``post_migrate`` after the plan."""
    dep = _paused_beneath_its_log()

    call_command("migrate", verbosity=0)

    assert _row(dep) == (D.PAUSED, 2)
    assert len(_log(dep)) == 2


def test_the_upgrade_repair_is_this_apps_on_the_decisions_database_at_the_stamp():
    """Only this app's signal, only the default database, and only a schema that
    has the decision columns the live model reads -- the guard the keyring
    receiver keeps, for the same crashes."""
    dep = _paused_beneath_its_log()
    below = ProjectState.from_apps(live_apps)
    below.remove_field("assurance", "deployment", "decision_keyring")

    signals.repair_decisions_behind_their_log(sender=object(), using="default")
    signals.repair_decisions_behind_their_log(sender=_assurance(), using="other")
    signals.repair_decisions_behind_their_log(sender=_assurance(), using="default", apps=below.apps)
    signals.repair_decisions_behind_their_log(
        sender=_assurance(), using="default", apps=ProjectState().apps
    )
    assert _row(dep) == (D.READY, 1)

    signals.repair_decisions_behind_their_log(sender=_assurance(), using="default", apps=live_apps)
    assert _row(dep) == (D.PAUSED, 2)
