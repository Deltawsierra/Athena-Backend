"""Each approval version names who declared it (owner-approved 1 Nov).

#198 served every recorded version of each approval (``approval-history/``) and could
not say who declared one: ``ApprovalVersion`` had no actor column, so the history said
what each approval was and when, and never whose change it was. A version is
change-control evidence only when it names the person whose write moved the approval to
it. It now does (``ApprovalVersion.declared_by``, migration 0083):

- the approved-workflows PUT is a signed-in person's, and every version it writes names
  that person: the version its final note writes, and each one noted between its own
  writes (a workflow withdrawn, a tool released, a tool bound), which a signal notes;
- code that binds a workflow's tools names the actor it binds as;
- a version noted with nobody behind it names no one: the decision refresh's catch-up
  note, and a write from a shell or a data fix. Never a guess, even when the approval's
  ``approved_by`` names someone: that is who last declared the approval as it stands,
  not who moved it to a given version;
- a version recorded before the column existed stays null. Nothing is backfilled;
- the approval-history read serves it beside the version's other fields, null as null,
  and an account that is removed reads as null, as ``bound_by`` does.

Every instant is passed explicitly: the clock is held. On master the column does not
exist, so every test here fails there.
"""

from __future__ import annotations

import pytest
from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as dj_timezone

from assurance import approval_history
from assurance import tool_contract as tc
from assurance.authority_chain_records import approval_digest
from assurance.decision import refresh_stored_decisions
from assurance.models import ApprovalVersion, ApprovedWorkflow, Asset
from tests.test_the_recorded_histories_are_served_to_the_person import (
    _REAL_NOW,
    T0,
    Clock,
    User,
    _client,
    _deployment,
    _tool,
    _url,
    _user,
    at,
    stamp,
)

pytestmark = pytest.mark.django_db

REFUND = {"kind": "tool", "identifier": "refund@payments"}
CRM = {"kind": "mcp_server", "identifier": "crm-mcp"}


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """Hold the clock: ``timezone.now`` and every model default that is it."""
    held = Clock(T0)
    monkeypatch.setattr(dj_timezone, "now", held.now)
    for model in apps.get_models():
        for fld in model._meta.concrete_fields:
            if fld.default is _REAL_NOW:
                monkeypatch.setitem(fld.__dict__, "_get_default", held.now)
    return held


def _put(person, dep, workflows):
    answer = _client(person).put(_url(dep, "approved-workflows"), {"workflows": workflows}, format="json")
    assert answer.status_code == 200, answer.content
    return answer


def _refund(description="refunds under 500", tools=(REFUND,)):
    return {"slug": "refund", "name": "Refund", "description": description, "tools": list(tools)}


def _recorded(dep):
    """Every version of ``dep``'s approvals, oldest first: ``(workflow, withdrawn,
    in_force_from, declarer's username or None)``."""
    return [
        (v.workflow, not v.digest, v.in_force_from, v.declared_by.username if v.declared_by_id else None)
        for v in ApprovalVersion.objects.filter(deployment=dep).select_related("declared_by").order_by(
            "in_force_from", "id"
        )
    ]


def _served(reader, dep, **params):
    """The approval-history read of ``dep``, oldest first, in the shape of :func:`_recorded`."""
    answer = _client(reader).get(_url(dep, "approval-history"), params)
    assert answer.status_code == 200, answer.content
    return [
        (v["workflow"], v["withdrawn"], v["in_force_from"], v["declared_by"])
        for v in reversed(answer.json()["versions"])
    ]


def _stamped(rows):
    return [(w, gone, stamp(instant), who) for w, gone, instant, who in rows]


# ------------------------------------------------------------------ the person's PUT


def test_a_declaration_and_a_withdrawal_by_one_person_then_another_each_name_their_own_declarer(
    clock, engine_keyring
):
    alice, bob = _user("alice", User.Roles.ADMIN), _user("bob", User.Roles.ADMIN)
    dep = _deployment(alice)
    _tool(dep, "refund@payments")

    clock.set(at(1))
    _put(alice, dep, [_refund()])  # declared
    clock.set(at(2))
    _put(alice, dep, [])  # withdrawn
    clock.set(at(3))
    _put(bob, dep, [_refund()])  # declared again
    clock.set(at(4))
    _put(bob, dep, [])  # withdrawn again

    expected = [
        ("refund", False, at(1), "alice"),
        ("refund", True, at(2), "alice"),
        ("refund", False, at(3), "bob"),
        ("refund", True, at(4), "bob"),
    ]
    assert _recorded(dep) == expected
    assert _served(alice, dep) == _stamped(expected)


def test_every_version_noted_between_one_puts_own_writes_names_that_puts_person(clock, engine_keyring):
    """One PUT can move an approval more than once: rewriting what a workflow is
    approved to do and swapping its tool releases the old binding (a version with no
    tool) and binds the new one (a version with it), each noted by a signal in the
    PUT's transaction. Both are the person's. A PUT whose only change is the
    description is noted by its own final note, and that version is the person's too."""
    alice, bob = _user("alice", User.Roles.ADMIN), _user("bob", User.Roles.ADMIN)
    dep = _deployment(alice)
    _tool(dep, "refund@payments")
    _tool(dep, "crm-mcp", kind=Asset.Kind.MCP_SERVER)

    clock.set(at(1))
    _put(alice, dep, [_refund(), {"slug": "export", "name": "Export"}])
    clock.set(at(2))
    _put(bob, dep, [_refund("refunds under 100", tools=[CRM]), {"slug": "export", "name": "Export"}])
    clock.set(at(3))
    _put(alice, dep, [_refund("refunds under 50", tools=[CRM]), {"slug": "export", "name": "Export"}])

    versions = list(ApprovalVersion.objects.filter(deployment=dep).order_by("in_force_from", "id"))
    by_instant = {}
    for version in versions:
        by_instant.setdefault(version.in_force_from, []).append(
            (version.workflow, [tuple(t[:2]) for t in version.tools], version.declared_by.username)
        )
    assert by_instant == {
        at(1): [("export", [], "alice"), ("refund", [("tool", "refund@payments")], "alice")],
        # Bob's one PUT: the refund tool released, then the CRM server bound.
        at(2): [("refund", [], "bob"), ("refund", [("mcp_server", "crm-mcp")], "bob")],
        # Alice's: the description alone, noted by the PUT's own final note.
        at(3): [("refund", [("mcp_server", "crm-mcp")], "alice")],
    }
    served = _served(alice, dep, workflow="refund")
    assert [who for *_rest, who in served] == ["alice", "bob", "bob", "alice"]


def test_code_that_binds_a_workflows_tools_names_the_actor_it_binds_as_and_none_without_one(clock):
    alice = _user("alice", User.Roles.ADMIN)
    dep = _deployment(alice)
    refund = _tool(dep, "refund@payments")
    crm = _tool(dep, "crm-mcp", kind=Asset.Kind.MCP_SERVER)
    ApprovedWorkflow.objects.bulk_create([ApprovedWorkflow(deployment=dep, slug="refund", name="Refund")])
    workflow = ApprovedWorkflow.objects.get(deployment=dep, slug="refund")

    clock.set(at(1))
    tc.bind_workflow(workflow, refund, actor=alice)
    clock.set(at(2))
    tc.approve_workflow_tools(workflow, [CRM], actor=alice)
    clock.set(at(3))
    tc.bind_workflow(workflow, refund)  # no actor: nobody is named

    assert _recorded(dep) == [
        ("refund", False, at(1), "alice"),
        # approve_workflow_tools: refund released, then crm bound, both alice's.
        ("refund", False, at(2), "alice"),
        ("refund", False, at(2), "alice"),
        ("refund", False, at(3), None),
    ]
    assert [sorted(tuple(t[:2]) for t in v.tools) for v in ApprovalVersion.objects.order_by("in_force_from", "id")] == [
        [("tool", "refund@payments")],
        [],
        [(crm.kind, crm.identifier)],
        [(crm.kind, crm.identifier), ("tool", "refund@payments")],
    ]


# --------------------------------------------------------------- nobody behind it


def test_a_version_noted_with_nobody_behind_it_names_no_one_and_never_a_guess(clock, engine_keyring):
    alice = _user("alice", User.Roles.ADMIN)
    dep = _deployment(alice)

    # A shell or a data fix saves an approval. Its signal notes the version, and no
    # person's write is behind it: null, though the approval names alice as its approver.
    clock.set(at(1))
    ApprovedWorkflow.objects.create(deployment=dep, slug="refund", name="Refund", description="d1",
                                    approved_by=alice)
    # A bulk write no signal sees, caught up by the decision refresh's note: the system
    # repair path, null.
    clock.set(at(2))
    ApprovedWorkflow.objects.filter(deployment=dep, slug="refund").update(description="d2")
    refresh_stored_decisions([dep.pk])
    # The catch-up note names no one even when it runs while a person is declaring on
    # the same context: what it catches up is a change no write of theirs noted.
    clock.set(at(3))
    ApprovedWorkflow.objects.filter(deployment=dep, slug="refund").update(description="d3")
    with approval_history.declaring(alice):
        approval_history.note_approvals_quietly(dep)
    # And deleting it from a shell notes the withdrawal with nobody named.
    clock.set(at(4))
    ApprovedWorkflow.objects.get(deployment=dep, slug="refund").delete()

    expected = [
        ("refund", False, at(1), None),
        ("refund", False, at(2), None),
        ("refund", False, at(3), None),
        ("refund", True, at(4), None),
    ]
    assert _recorded(dep) == expected
    assert _served(alice, dep) == _stamped(expected)


def test_note_approvals_records_the_declarer_it_is_given_and_otherwise_none(clock):
    alice = _user("alice", User.Roles.ADMIN)
    dep = _deployment(alice)
    ApprovedWorkflow.objects.bulk_create([ApprovedWorkflow(deployment=dep, slug="refund", name="Refund")])
    clock.set(at(1))
    (given,) = approval_history.note_approvals(dep, now=at(1), declared_by=alice)
    ApprovedWorkflow.objects.filter(deployment=dep).update(description="moved")
    (unnamed,) = approval_history.note_approvals(dep, now=at(2))
    assert (given.declared_by_id, unnamed.declared_by_id) == (alice.pk, None)
    # Outside any declaration, nobody is declaring.
    assert approval_history.who_is_declaring() is None
    with approval_history.declaring(alice):
        assert approval_history.who_is_declaring() == alice
    assert approval_history.who_is_declaring() is None


# ------------------------------------------------------------- what was there before

_BEFORE = ("assurance", "0082_retest_check")
_AFTER = ("assurance", "0083_approval_version_declared_by")


def _migrate(target):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate([target])


def _columns():
    with connection.cursor() as cursor:
        return {c.name for c in connection.introspection.get_table_description(cursor, ApprovalVersion._meta.db_table)}


@pytest.mark.django_db(transaction=True)
def test_a_version_recorded_before_the_column_reads_not_recorded_and_is_never_backfilled(clock, engine_keyring):
    alice, bob = _user("alice", User.Roles.ADMIN), _user("bob", User.Roles.ADMIN)
    dep = _deployment(alice)
    # The approval as alice declared it before this column existed.
    ApprovedWorkflow.objects.bulk_create(
        [ApprovedWorkflow(deployment=dep, slug="refund", name="Refund", description="d1", approved_by=alice)]
    )
    workflow = ApprovedWorkflow.objects.get(deployment=dep, slug="refund")
    head = MigrationExecutor(connection).loader.graph.leaf_nodes("assurance")[0]
    try:
        _migrate(_BEFORE)
        assert "declared_by_id" not in _columns()
        # The version the code before this noted for it, written as it was stored.
        old = MigrationExecutor(connection).loader.project_state(_BEFORE).apps
        old.get_model("assurance", "ApprovalVersion").objects.create(
            deployment_id=dep.pk, workflow="refund", digest=approval_digest(workflow, []), tools=[],
            in_force_from=at(1), recorded_at=at(1),
        )
        _migrate(_AFTER)
        assert "declared_by_id" in _columns()
    finally:
        _migrate(head)

    (before,) = ApprovalVersion.objects.filter(deployment=dep)
    # Not alice, though she is the approval's approver: who moved it to this version is
    # not on record, so it reads as not recorded.
    assert before.declared_by_id is None
    assert _served(alice, dep) == [("refund", False, stamp(at(1)), None)]

    # The next person's write names them; the version before stays as it was.
    clock.set(at(2))
    _put(bob, dep, [{"slug": "refund", "name": "Refund", "description": "d2"}])
    assert _served(alice, dep) == [
        ("refund", False, stamp(at(1)), None),
        ("refund", False, stamp(at(2)), "bob"),
    ]


# ------------------------------------------------------------------------ the read


def test_the_history_read_serves_who_declared_each_version_beside_its_other_fields(clock, engine_keyring):
    alice, bob = _user("alice", User.Roles.ADMIN), _user("bob", User.Roles.ADMIN)
    viewer = _user("viewer")
    dep = _deployment(viewer)
    clock.set(at(1))
    _put(bob, dep, [{"slug": "refund", "name": "Refund"}])
    clock.set(at(2))
    _put(alice, dep, [])
    (declared, withdrawn) = ApprovalVersion.objects.filter(deployment=dep).order_by("in_force_from", "id")

    answer = _client(viewer).get(_url(dep, "approval-history"))

    assert answer.status_code == 200, answer.content
    assert answer.json()["versions"] == [
        {
            "version": str(withdrawn.id), "workflow": "refund", "digest": None, "withdrawn": True,
            "in_force_from": stamp(at(2)), "in_force_until": None, "recorded_at": stamp(at(2)),
            "declared_by": "alice", "tools": [],
        },
        {
            "version": str(declared.id), "workflow": "refund", "digest": declared.digest, "withdrawn": False,
            "in_force_from": stamp(at(1)), "in_force_until": stamp(at(2)), "recorded_at": stamp(at(1)),
            "declared_by": "bob", "tools": [],
        },
    ]

    # Removing an account is never held back by a version it declared, and the version
    # then reads as not recorded -- as a binding's `bound_by` does.
    bob.delete()
    served = _client(viewer).get(_url(dep, "approval-history")).json()["versions"]
    assert [v["declared_by"] for v in served] == ["alice", None]
    assert ApprovalVersion.objects.filter(deployment=dep).count() == 2


def test_who_declared_each_version_costs_no_query_per_version():
    viewer = _user("viewer")
    client = _client(viewer)
    one, many = _deployment(viewer, name="one"), _deployment(viewer, name="many")
    people = [_user(f"declarer-{i}", User.Roles.ADMIN) for i in range(20)]
    ApprovalVersion.objects.bulk_create(
        [ApprovalVersion(deployment=one, workflow="w", digest="a" * 64, tools=[], in_force_from=at(0),
                         declared_by=people[0])]
    )
    ApprovalVersion.objects.bulk_create(
        ApprovalVersion(deployment=many, workflow=f"w{i}", digest=f"{i:064x}", tools=[], in_force_from=at(i),
                        declared_by=people[i])
        for i in range(20)
    )
    with CaptureQueriesContext(connection) as single:
        assert client.get(_url(one, "approval-history")).status_code == 200
    with CaptureQueriesContext(connection) as page:
        served = client.get(_url(many, "approval-history")).json()["versions"]
    assert [v["declared_by"] for v in served] == [f"declarer-{i}" for i in reversed(range(20))]
    assert len(page.captured_queries) == len(single.captured_queries)
