"""The histories this backend records are served to the person, read-only (field guide G10).

Three records were kept and not served to an operator:

- every version of each workflow approval (``ApprovalVersion``). The only route that
  read it is the approval-in-force route, which authenticates Achilles' gate credential
  only and answers an operator's session 403;
- every recorded tool contract (``ToolContract``, append-only) and every binding to one,
  with its ``invalidated_at`` / ``invalidation_reason``. The contract in force was served
  only for a tool an approval binds;
- every accepted change of the decision (``DecisionTransition``). Only the decision in
  force and its revision were served.

Four GET routes on the deployment now serve them (``assurance/history_reads.py``):
``approval-history/``, ``tool-contracts/``, ``tool-contract-bindings/`` and
``decision-history/``. These tests hold that each one:

- maps every recorded field, and a field the record never held is null, never 0 or "";
- answers a person not signed in 401, and a deployment the person cannot read exactly as
  the approved-workflows, authority-chains and decision-support reads answer it;
- takes no write method, and writes nothing when read;
- is bounded, says so, and pages with ``?offset=``;

and that the gate's approval-in-force route is exactly as it was.

Every instant is passed explicitly: the clock is held, and nothing here reads the wall
clock. On master these routes do not exist, so every test below that reads one fails
there; the test of the gate's route passes there as it passes here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import resolve
from django.utils import timezone as dj_timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.settings import api_settings
from rest_framework.test import APIClient

from assurance import gate_approval
from assurance import tool_contract as tc
from assurance.models import (
    ApprovalVersion,
    ApprovedWorkflow,
    Asset,
    DecisionTransition,
    Deployment,
    ToolContract,
    ToolContractBinding,
)
from assurance.revision import accept_transition
from assurance.views import DeploymentViewSet
from safety import stops

pytestmark = pytest.mark.django_db

User = get_user_model()

#: The held clock's start. Every instant below is an offset from it.
T0 = datetime(2026, 10, 1, 9, 0, tzinfo=dt_timezone.utc)
_REAL_NOW = dj_timezone.now

READ_TOKEN = "gate-approval-read-token-for-history-tests-0123"  # pragma: allowlist secret

HISTORY_ROUTES = ("approval-history", "tool-contracts", "tool-contract-bindings", "decision-history")
#: The current-state reads the histories extend, whose answers they mirror.
CURRENT_READS = ("approved-workflows", "authority-chains", "decision-support")

C1, C2, C3 = "1" * 64, "2" * 64, "3" * 64


def at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


def stamp(instant: datetime) -> str:
    """An aware datetime as the API renders one (DRF's encoder: ISO 8601, ``Z``)."""
    return instant.isoformat().replace("+00:00", "Z")


class Clock:
    def __init__(self, start: datetime):
        self.at = start

    def now(self) -> datetime:
        return self.at

    def set(self, instant: datetime) -> datetime:
        self.at = instant
        return instant


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """Hold the clock: ``timezone.now`` and every model default that is it. A test sets
    each instant it needs; nothing reads the wall clock."""
    held = Clock(T0)
    monkeypatch.setattr(dj_timezone, "now", held.now)
    for model in apps.get_models():
        for fld in model._meta.concrete_fields:
            if fld.default is _REAL_NOW:
                monkeypatch.setitem(fld.__dict__, "_get_default", held.now)
    return held


@pytest.fixture
def gate(monkeypatch):
    """Achilles' gate, with its approval-read credential."""
    User.objects.create_user(username="gate-reader", password="x")
    monkeypatch.setenv(gate_approval.TOKEN_ENV, READ_TOKEN)
    monkeypatch.setenv(gate_approval.USER_ENV, "gate-reader")
    client = APIClient()
    client.credentials(HTTP_X_GATE_APPROVAL_TOKEN=READ_TOKEN)
    return client


def _user(name: str, role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.VIEWER)


def _client(user) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _deployment(owner, name="support-agent") -> Deployment:
    return Deployment.objects.create(name=name, owner=owner)


def _url(deployment_or_uuid, route: str) -> str:
    key = getattr(deployment_or_uuid, "uuid", deployment_or_uuid)
    return f"/api/assurance/deployments/{key}/{route}/"


def _tool(dep, identifier, kind=Asset.Kind.TOOL, **contract):
    metadata = {"permissions": ["payments:read"], "server": "payments", **contract}
    return Asset.objects.create(
        deployment=dep, kind=kind, name=identifier.split("@")[0], identifier=identifier,
        classification=Asset.Classification.APPROVED, metadata=metadata,
    )


def _redeclare(asset, **changes):
    asset.metadata = {**asset.metadata, **changes}
    asset.save(update_fields=["metadata"])
    return asset


def _record_everything(dep):
    """One row of every history on ``dep``, written without the signals, so a test can
    show a deployment's record is not served to someone who cannot read it."""
    ApprovalVersion.objects.bulk_create(
        [ApprovalVersion(deployment=dep, workflow="refund", digest=C1, tools=[], in_force_from=at(1))]
    )
    ToolContract.objects.bulk_create(
        [ToolContract(deployment=dep, tool_kind="tool", tool_identifier="refund@payments", digest=C1, recorded_at=at(1))]
    )
    ToolContractBinding.objects.bulk_create(
        [ToolContractBinding(deployment=dep, claim_fingerprint="f" * 64, tool_kind="tool",
                             tool_identifier="refund@payments", contract_digest=C1, bound_at=at(1))]
    )
    DecisionTransition.objects.bulk_create(
        [DecisionTransition(deployment=dep, revision=1, from_decision="", to_decision="ready")]
    )


def _row_counts():
    return {
        model.__name__: model.objects.count()
        for model in (ApprovalVersion, ApprovedWorkflow, ToolContract, ToolContractBinding, DecisionTransition)
    }


# ----------------------------------------------------------------- approval history


def test_each_approval_version_is_served_as_recorded_and_what_was_never_recorded_is_null():
    viewer = _user("viewer")
    dep = _deployment(viewer)
    binder = _user("binder", User.Roles.ADMIN)
    # The approval as it stands, and its bindings, written without the signals so the
    # history is exactly the rows below: the first binding was released when the tool
    # was re-bound under a changed contract, after the invalidation engine had found it
    # superseded; the second was bound by code, with no actor recorded.
    ApprovedWorkflow.objects.bulk_create(
        [ApprovedWorkflow(deployment=dep, slug="refund", name="Refund", approved_by=binder)]
    )
    workflow = ApprovedWorkflow.objects.get(deployment=dep, slug="refund")
    ToolContractBinding.objects.bulk_create(
        [
            ToolContractBinding(
                deployment=dep, workflow=workflow, tool_kind="tool", tool_identifier="refund@payments",
                contract_digest=C1, bound_by=binder, bound_at=at(10), released_at=at(20),
                invalidated_at=at(15), invalidation_reason="Tool contract changed: refund@payments",
            ),
            ToolContractBinding(
                deployment=dep, workflow=workflow, tool_kind="tool", tool_identifier="refund@payments",
                contract_digest=C2, bound_by=None, bound_at=at(20),
            ),
        ]
    )
    ApprovalVersion.objects.bulk_create(
        [
            # `export` was approved, then withdrawn: withdrawing deleted its bindings, so
            # its first version names its tool and digest, and no binding.
            ApprovalVersion(deployment=dep, workflow="export", digest="e" * 64,
                            tools=[["mcp_server", "files-mcp", C3]], in_force_from=at(5), recorded_at=at(5)),
            ApprovalVersion(deployment=dep, workflow="refund", digest="a" * 64,
                            tools=[["tool", "refund@payments", C1]], in_force_from=at(10), recorded_at=at(10)),
            ApprovalVersion(deployment=dep, workflow="refund", digest="b" * 64,
                            tools=[["tool", "refund@payments", C2]], in_force_from=at(20), recorded_at=at(21)),
            ApprovalVersion(deployment=dep, workflow="export", digest="", tools=[],
                            in_force_from=at(30), recorded_at=at(30)),
        ]
    )
    ids = {(v.workflow, v.in_force_from): str(v.id) for v in ApprovalVersion.objects.all()}

    answer = _client(viewer).get(_url(dep, "approval-history"))

    assert answer.status_code == 200, answer.content
    unbound = {"bound_at": None, "bound_by": None, "released_at": None, "invalidated_at": None,
               "invalidation_reason": None}
    assert answer.json() == {
        "deployment": str(dep.uuid),
        "workflow": None,
        "versions": [
            {
                "version": ids[("export", at(30))], "workflow": "export", "digest": None, "withdrawn": True,
                "in_force_from": stamp(at(30)), "in_force_until": None, "recorded_at": stamp(at(30)),
                "tools": [],
            },
            {
                "version": ids[("refund", at(20))], "workflow": "refund", "digest": "b" * 64, "withdrawn": False,
                "in_force_from": stamp(at(20)), "in_force_until": None, "recorded_at": stamp(at(21)),
                "tools": [{"kind": "tool", "identifier": "refund@payments", "contract_digest": C2,
                           **unbound, "bound_at": stamp(at(20))}],
            },
            {
                "version": ids[("refund", at(10))], "workflow": "refund", "digest": "a" * 64, "withdrawn": False,
                "in_force_from": stamp(at(10)), "in_force_until": stamp(at(20)), "recorded_at": stamp(at(10)),
                "tools": [{"kind": "tool", "identifier": "refund@payments", "contract_digest": C1,
                           "bound_at": stamp(at(10)), "bound_by": "binder", "released_at": stamp(at(20)),
                           "invalidated_at": stamp(at(15)),
                           "invalidation_reason": "Tool contract changed: refund@payments"}],
            },
            {
                "version": ids[("export", at(5))], "workflow": "export", "digest": "e" * 64, "withdrawn": False,
                "in_force_from": stamp(at(5)), "in_force_until": stamp(at(30)), "recorded_at": stamp(at(5)),
                "tools": [{"kind": "mcp_server", "identifier": "files-mcp", "contract_digest": C3, **unbound}],
            },
        ],
        "version_count": 4,
        "returned": 4,
        "truncated": False,
        "page_size": DeploymentViewSet.APPROVAL_HISTORY_PAGE_SIZE,
        "offset": 0,
    }


def test_a_tool_dropped_and_approved_again_under_the_same_contract_names_the_binding_live_then():
    """Two bindings of one tool under one contract digest, one after the other: each
    version names the binding that was live when it came into force, never the later
    one."""
    viewer = _user("viewer")
    dep = _deployment(viewer)
    first, second = _user("first", User.Roles.ADMIN), _user("second", User.Roles.ADMIN)
    ApprovedWorkflow.objects.bulk_create([ApprovedWorkflow(deployment=dep, slug="refund", name="Refund")])
    workflow = ApprovedWorkflow.objects.get(deployment=dep, slug="refund")
    ToolContractBinding.objects.bulk_create(
        [
            ToolContractBinding(deployment=dep, workflow=workflow, tool_kind="tool", tool_identifier="refund@payments",
                                contract_digest=C1, bound_by=first, bound_at=at(10), released_at=at(20)),
            ToolContractBinding(deployment=dep, workflow=workflow, tool_kind="tool", tool_identifier="refund@payments",
                                contract_digest=C1, bound_by=second, bound_at=at(30)),
        ]
    )
    tool = [["tool", "refund@payments", C1]]
    ApprovalVersion.objects.bulk_create(
        [
            ApprovalVersion(deployment=dep, workflow="refund", digest="a" * 64, tools=tool, in_force_from=at(10)),
            ApprovalVersion(deployment=dep, workflow="refund", digest="b" * 64, tools=[], in_force_from=at(20)),
            ApprovalVersion(deployment=dep, workflow="refund", digest="a" * 64, tools=tool, in_force_from=at(30)),
        ]
    )

    versions = _client(viewer).get(_url(dep, "approval-history")).json()["versions"]

    assert [(v["in_force_from"], [(t["bound_at"], t["bound_by"], t["released_at"]) for t in v["tools"]])
            for v in versions] == [
        (stamp(at(30)), [(stamp(at(30)), "second", None)]),
        (stamp(at(20)), []),
        (stamp(at(10)), [(stamp(at(10)), "first", stamp(at(20)))]),
    ]

    # A version noted after the only binding of its tool on record was released (a note
    # that came late): no binding was live then, so none is named -- never the released one.
    ApprovalVersion.objects.bulk_create(
        [ApprovalVersion(deployment=dep, workflow="refund", digest="c" * 64,
                         tools=[["tool", "refund@payments", C1]], in_force_from=at(25))]
    )
    late = _client(viewer).get(_url(dep, "approval-history")).json()["versions"][1]
    assert late["in_force_from"] == stamp(at(25))
    assert [(t["bound_at"], t["bound_by"], t["released_at"]) for t in late["tools"]] == [(None, None, None)]


def test_one_approvals_history_is_read_by_its_slug_and_a_slug_that_is_not_one_is_refused():
    viewer = _user("viewer")
    dep = _deployment(viewer)
    ApprovalVersion.objects.bulk_create(
        [
            ApprovalVersion(deployment=dep, workflow="refund", digest=C1, tools=[], in_force_from=at(1)),
            ApprovalVersion(deployment=dep, workflow="export", digest=C2, tools=[], in_force_from=at(2)),
            ApprovalVersion(deployment=dep, workflow="refund", digest=C3, tools=[], in_force_from=at(3)),
        ]
    )
    client = _client(viewer)

    one = client.get(_url(dep, "approval-history"), {"workflow": "refund"}).json()
    assert one["workflow"] == "refund" and one["version_count"] == 2
    assert [v["digest"] for v in one["versions"]] == [C3, C1]
    assert one["versions"][1]["in_force_until"] == stamp(at(3)), "the next version is the same workflow's"

    nobody = client.get(_url(dep, "approval-history"), {"workflow": "never-approved"}).json()
    assert (nobody["versions"], nobody["version_count"], nobody["truncated"]) == ([], 0, False)

    for bad in ("", "a b", "../refund", "x" * 201, "refund?"):
        refused = client.get(_url(dep, "approval-history"), {"workflow": bad})
        assert refused.status_code == 400, bad
        assert "workflow" in refused.json()


def test_the_history_the_approved_workflows_route_writes_is_served_with_who_bound_each_tool(clock, engine_keyring, gate):
    """Through the real write path: an admin approves a workflow's tool, the tool's
    contract changes, the admin re-approves it. The person reads every version the
    history noted, and the version the gate reads in force is the newest one served."""
    admin = _user("approver", User.Roles.ADMIN)
    dep = _deployment(admin)
    refund = _tool(dep, "refund@payments", input_schema={"type": "object"})
    client = _client(admin)
    body = {"workflows": [{"slug": "refund", "name": "Refund", "description": "refunds under 500",
                           "tools": [{"kind": "tool", "identifier": "refund@payments"}]}]}

    clock.set(at(1))
    assert client.put(_url(dep, "approved-workflows"), body, format="json").status_code == 200
    first_digest = tc.contract_digest(refund)
    clock.set(at(2))
    _redeclare(refund, effect_class="destructive")
    clock.set(at(3))
    assert client.put(_url(dep, "approved-workflows"), body, format="json").status_code == 200
    second_digest = tc.contract_digest(refund)
    assert first_digest != second_digest

    served = client.get(_url(dep, "approval-history"), {"workflow": "refund"}).json()

    recorded = list(ApprovalVersion.objects.filter(deployment=dep, workflow="refund").order_by("-in_force_from", "-id"))
    assert [v["version"] for v in served["versions"]] == [str(r.id) for r in recorded]
    assert [v["digest"] for v in served["versions"]] == [r.digest for r in recorded]
    assert served["version_count"] == len(recorded)
    newest, oldest = served["versions"][0], served["versions"][-1]
    assert newest["tools"] == [
        {"kind": "tool", "identifier": "refund@payments", "contract_digest": second_digest,
         "bound_at": stamp(at(3)), "bound_by": "approver", "released_at": None, "invalidated_at": None,
         "invalidation_reason": None}
    ]
    assert newest["in_force_until"] is None
    assert oldest["in_force_from"] == stamp(at(1)) and oldest["in_force_until"] == stamp(at(3))
    assert oldest["tools"] == [
        {"kind": "tool", "identifier": "refund@payments", "contract_digest": first_digest,
         "bound_at": stamp(at(1)), "bound_by": "approver", "released_at": stamp(at(3)), "invalidated_at": None,
         "invalidation_reason": None}
    ]
    # The person's read names the same version the gate reads in force.
    in_force = gate.get(_url(dep, "workflows/refund/approval-in-force")).json()
    assert (in_force["version"], in_force["digest"]) == (newest["version"], newest["digest"])


# ------------------------------------------------------------ tool contract history


def test_every_recorded_tool_contract_is_served_with_the_one_in_force_bound_or_not(clock):
    viewer = _user("viewer")
    dep = _deployment(viewer)
    refund = _tool(dep, "refund@payments", input_schema={"type": "object"})
    crm = _tool(dep, "crm-mcp", kind=Asset.Kind.MCP_SERVER)
    before = tc.contract_descriptor(refund)
    tc.record_tool_contracts(dep, now=at(0))
    clock.set(at(10))
    _redeclare(refund, effect_class="destructive")
    tc.record_tool_contracts(dep, now=at(10))
    # `crm-mcp` leaves the graph: its recorded contract stays, and nothing is in force.
    _redeclare(crm, retired=True)
    # Nothing approves either tool: the contract in force is served all the same.
    assert not ToolContractBinding.objects.exists()

    answer = _client(viewer).get(_url(dep, "tool-contracts"))

    assert answer.status_code == 200, answer.content
    rows = list(ToolContract.objects.filter(deployment=dep).order_by("-id"))
    first = {(r.tool_identifier, r.recorded_at): r for r in rows}
    refund_now = tc.contract_digest(refund)
    expected = {
        ("refund@payments", at(10)): {
            "kind": "tool", "identifier": "refund@payments", "digest": refund_now,
            "contract": tc.contract_descriptor(refund), "recorded_at": stamp(at(10)), "superseded_at": None,
            "current_digest": refund_now, "in_force": True,
        },
        ("refund@payments", at(0)): {
            "kind": "tool", "identifier": "refund@payments", "digest": first[("refund@payments", at(0))].digest,
            "contract": before, "recorded_at": stamp(at(0)), "superseded_at": stamp(at(10)),
            "current_digest": refund_now, "in_force": False,
        },
        ("crm-mcp", at(0)): {
            "kind": "mcp_server", "identifier": "crm-mcp", "digest": first[("crm-mcp", at(0))].digest,
            "contract": first[("crm-mcp", at(0))].contract, "recorded_at": stamp(at(0)), "superseded_at": None,
            "current_digest": None, "in_force": False,
        },
    }
    assert answer.json() == {
        "deployment": str(dep.uuid),
        "kind": None,
        "identifier": None,
        "contracts": [expected[(r.tool_identifier, r.recorded_at)] for r in rows],
        "contract_count": 3,
        "returned": 3,
        "truncated": False,
        "page_size": DeploymentViewSet.HISTORY_PAGE_SIZE,
        "offset": 0,
    }
    assert expected[("refund@payments", at(0))]["digest"] != refund_now

    # A contract that moved and was not recorded yet: the newest recorded one is not in
    # force, and the digest in force is served as it is now.
    _redeclare(refund, annotations={"destructiveHint": True})
    newest = _client(viewer).get(_url(dep, "tool-contracts")).json()["contracts"][0]
    assert newest["digest"] == refund_now
    assert newest["current_digest"] == tc.contract_digest(refund) != refund_now
    assert newest["in_force"] is False


def test_a_contract_that_moved_away_and_came_back_is_in_force_only_as_its_newest_row(clock):
    """The history appends a contract that returns to an earlier digest: the earlier row
    of the same digest is superseded, not in force a second time."""
    viewer = _user("viewer")
    dep = _deployment(viewer)
    refund = _tool(dep, "refund@payments")
    tc.record_tool_contracts(dep, now=at(0))
    _redeclare(refund, effect_class="destructive")
    tc.record_tool_contracts(dep, now=at(1))
    _redeclare(refund, effect_class=None)
    tc.record_tool_contracts(dep, now=at(2))

    contracts = _client(viewer).get(_url(dep, "tool-contracts")).json()["contracts"]

    back, away, first = contracts
    assert back["digest"] == first["digest"] == tc.contract_digest(refund) != away["digest"]
    assert [c["in_force"] for c in contracts] == [True, False, False]
    assert [c["superseded_at"] for c in contracts] == [None, stamp(at(2)), stamp(at(1))]


def test_one_registrations_contracts_are_read_by_kind_and_identifier_and_a_bad_filter_is_refused():
    viewer = _user("viewer")
    dep = _deployment(viewer)
    _tool(dep, "refund@payments")
    _tool(dep, "crm-mcp", kind=Asset.Kind.MCP_SERVER)
    tc.record_tool_contracts(dep, now=at(0))
    client = _client(viewer)

    for route in ("tool-contracts", "tool-contract-bindings"):
        narrowed = client.get(_url(dep, route), {"kind": "mcp_server", "identifier": "crm-mcp"}).json()
        assert (narrowed["kind"], narrowed["identifier"]) == ("mcp_server", "crm-mcp")
        for refused in ({"kind": "agent"}, {"kind": ""}, {"identifier": ""}, {"identifier": "x" * 1025}):
            answer = client.get(_url(dep, route), refused)
            assert answer.status_code == 400, (route, refused)
            assert set(answer.json()) == set(refused), (route, refused)
    narrowed = client.get(_url(dep, "tool-contracts"), {"kind": "mcp_server", "identifier": "crm-mcp"}).json()
    assert [(c["kind"], c["identifier"]) for c in narrowed["contracts"]] == [("mcp_server", "crm-mcp")]
    assert narrowed["contract_count"] == 1


def test_every_binding_is_served_with_its_invalidation_and_a_released_one_is_not_called_superseded(clock):
    viewer = _user("viewer")
    admin = _user("approver", User.Roles.ADMIN)
    dep = _deployment(viewer)
    refund = _tool(dep, "refund@payments")
    workflow = ApprovedWorkflow.objects.create(deployment=dep, slug="refund", name="Refund", approved_by=admin)
    clock.set(at(1))
    old = tc.bind_workflow(workflow, refund, actor=admin, now=at(1))
    clock.set(at(2))
    _redeclare(refund, effect_class="destructive")
    clock.set(at(3))
    new = tc.bind_workflow(workflow, refund, actor=admin, now=at(3))
    clock.set(at(4))
    _redeclare(refund, effect_class="external")
    # The invalidation engine finds the live approval superseded and records it.
    clock.set(at(5))
    tc.invalidate_superseded(dep, [], system_fp="unused", now=at(5))
    # A claim that depends on the tool, bound by code under the contract in force.
    in_force = tc.contract_digest(refund)
    ToolContractBinding.objects.bulk_create(
        [ToolContractBinding(deployment=dep, claim_fingerprint="f" * 64, tool_kind="tool",
                             tool_identifier="refund@payments", contract_digest=in_force, bound_at=at(6))]
    )
    new.refresh_from_db()
    assert new.invalidated_at == at(5) and new.invalidation_reason

    answer = _client(viewer).get(_url(dep, "tool-contract-bindings"))

    assert answer.status_code == 200, answer.content
    assert answer.json() == {
        "deployment": str(dep.uuid),
        "kind": None,
        "identifier": None,
        "bindings": [
            {
                "subject": "claim", "workflow": None, "claim_fingerprint": "f" * 64, "kind": "tool",
                "identifier": "refund@payments", "contract_digest": in_force, "current_digest": in_force,
                "live": True, "superseded": False, "bound_at": stamp(at(6)), "bound_by": None,
                "released_at": None, "invalidated_at": None, "invalidation_reason": None,
            },
            {
                "subject": "workflow", "workflow": "refund", "claim_fingerprint": None, "kind": "tool",
                "identifier": "refund@payments", "contract_digest": new.contract_digest,
                "current_digest": in_force, "live": True, "superseded": True, "bound_at": stamp(at(3)),
                "bound_by": "approver", "released_at": None, "invalidated_at": stamp(at(5)),
                "invalidation_reason": new.invalidation_reason,
            },
            {
                "subject": "workflow", "workflow": "refund", "claim_fingerprint": None, "kind": "tool",
                "identifier": "refund@payments", "contract_digest": old.contract_digest,
                "current_digest": in_force, "live": False, "superseded": None, "bound_at": stamp(at(1)),
                "bound_by": "approver", "released_at": stamp(at(3)), "invalidated_at": None,
                "invalidation_reason": None,
            },
        ],
        "binding_count": 3,
        "returned": 3,
        "truncated": False,
        "page_size": DeploymentViewSet.HISTORY_PAGE_SIZE,
        "offset": 0,
    }
    assert "refund@payments" in new.invalidation_reason

    # The tool leaves the graph: nothing is in force, and every live binding is superseded.
    _redeclare(refund, retired=True)
    left = _client(viewer).get(_url(dep, "tool-contract-bindings")).json()["bindings"]
    assert [(b["current_digest"], b["superseded"]) for b in left] == [(None, True), (None, True), (None, None)]


# ---------------------------------------------------------------- decision history


def test_every_accepted_decision_change_is_served_newest_first_and_an_absent_one_is_null(clock):
    viewer = _user("viewer")
    dep = _deployment(viewer)
    clock.set(at(1))
    accept_transition(dep, to_decision=Deployment.Decision.READY, basis_digest="a" * 64)
    clock.set(at(2))
    accept_transition(dep, to_decision=Deployment.Decision.PAUSED)
    clock.set(at(3))
    accept_transition(dep, to_decision=None, basis_digest="b" * 64)
    DecisionTransition.objects.filter(deployment=dep, revision=1).update(delivered_at=at(9))

    answer = _client(viewer).get(_url(dep, "decision-history"))

    assert answer.status_code == 200, answer.content
    assert answer.json() == {
        "deployment": str(dep.uuid),
        "transitions": [
            {"revision": 3, "from_decision": "paused", "to_decision": None, "basis_digest": "b" * 64,
             "created_at": stamp(at(3)), "delivered_at": None},
            {"revision": 2, "from_decision": "ready", "to_decision": "paused", "basis_digest": None,
             "created_at": stamp(at(2)), "delivered_at": None},
            {"revision": 1, "from_decision": None, "to_decision": "ready", "basis_digest": "a" * 64,
             "created_at": stamp(at(1)), "delivered_at": stamp(at(9))},
        ],
        "transition_count": 3,
        "returned": 3,
        "truncated": False,
        "page_size": DeploymentViewSet.HISTORY_PAGE_SIZE,
        "offset": 0,
    }


def test_a_deployment_with_no_history_reads_empty_with_counts_of_zero_that_were_counted():
    viewer = _user("viewer")
    dep = _deployment(viewer)
    client = _client(viewer)
    for route, key in zip(HISTORY_ROUTES, ("versions", "contracts", "bindings", "transitions"), strict=True):
        body = client.get(_url(dep, route)).json()
        assert (body[key], body[f"{key[:-1]}_count"], body["returned"], body["truncated"]) == ([], 0, 0, False)


# ---------------------------------------------------------- who may read, and how


@pytest.mark.parametrize("route", HISTORY_ROUTES)
def test_a_person_not_signed_in_is_answered_401_as_the_current_reads_answer_them(route):
    dep = _deployment(_user("owner"))
    _record_everything(dep)
    anonymous = APIClient()

    answer = anonymous.get(_url(dep, route))

    assert answer.status_code == 401
    for current in CURRENT_READS:
        theirs = anonymous.get(_url(dep, current))
        assert (theirs.status_code, theirs.json()) == (answer.status_code, answer.json()), current


@pytest.mark.parametrize("route", HISTORY_ROUTES)
def test_a_deployment_the_person_cannot_read_is_answered_as_the_current_reads_answer_it(route):
    theirs = _deployment(_user("owner"))
    _record_everything(theirs)
    outsider = _client(_user("outsider"))

    for target in (theirs, uuid.uuid4(), "not-a-uuid"):
        for query in ({}, {"offset": "-1"}, {"offset": "5"}):
            answer = outsider.get(_url(target, route), query)
            assert answer.status_code == 404, (target, query)
            for current in CURRENT_READS:
                other = outsider.get(_url(target, current), query)
                assert (other.status_code, other.json()) == (answer.status_code, answer.json()), (target, current)
            assert C1 not in answer.content.decode(), "nothing recorded on their deployment is served"


@pytest.mark.parametrize("route", HISTORY_ROUTES)
def test_whoever_reads_the_current_state_reads_its_history(route, engine_keyring):
    """The owner, and a privileged reader of every deployment (an analyst, an admin), as
    the current-state reads allow; a viewer who owns nothing reads none of it."""
    owner = _user("owner")
    dep = _deployment(owner)
    _record_everything(dep)
    for reader in (owner, _user("analyst", User.Roles.ANALYST), _user("admin", User.Roles.ADMIN)):
        client = _client(reader)
        assert client.get(_url(dep, route)).status_code == 200, reader.username
        for current in CURRENT_READS:
            assert client.get(_url(dep, current)).status_code == 200, (reader.username, current)


@pytest.mark.parametrize("name", ["approval_history", "tool_contracts", "tool_contract_bindings", "decision_history"])
def test_each_history_read_is_a_get_with_the_viewsets_own_authentication_and_permission(name):
    read = getattr(DeploymentViewSet, name)
    assert read.detail is True and dict(read.mapping) == {"get": name}
    for mirrored in (DeploymentViewSet.approved_workflows, DeploymentViewSet.authority_chains,
                     DeploymentViewSet.decision_support, read):
        assert "authentication_classes" not in mirrored.kwargs and "permission_classes" not in mirrored.kwargs
    assert DeploymentViewSet.permission_classes == [IsAuthenticated]
    match = resolve(_url(uuid.uuid4(), name.replace("_", "-")))
    assert match.func.cls is DeploymentViewSet
    assert match.url_name == f"deployment-{name.replace('_', '-')}"
    assert stops.NOT_STOPS[match.url_name].keys() == {"GET"}
    assert match.url_name not in stops.STOP_ROUTES


@pytest.mark.parametrize("route", HISTORY_ROUTES)
@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_no_write_method_is_accepted_and_nothing_is_written(route, method):
    admin = _user("admin", User.Roles.ADMIN)
    dep = _deployment(admin)
    _record_everything(dep)
    before = _row_counts()

    answer = getattr(_client(admin), method)(_url(dep, route), {"versions": [], "transitions": []}, format="json")

    assert answer.status_code == 405, answer.content
    assert _row_counts() == before


# ------------------------------------------------------------- bounds and paging


def _fill(dep, route: str, count: int) -> None:
    """``count`` rows of ``route``'s history on ``dep``, one minute apart."""
    if route == "approval-history":
        ApprovalVersion.objects.bulk_create(
            ApprovalVersion(deployment=dep, workflow=f"w{i % 7}", digest=f"{i:064x}",
                            tools=[["tool", "refund@payments", C1]], in_force_from=at(i))
            for i in range(count)
        )
    elif route == "tool-contracts":
        ToolContract.objects.bulk_create(
            ToolContract(deployment=dep, tool_kind="tool", tool_identifier=f"t{i % 7}", digest=f"{i:064x}",
                         recorded_at=at(i))
            for i in range(count)
        )
    elif route == "tool-contract-bindings":
        ToolContractBinding.objects.bulk_create(
            ToolContractBinding(deployment=dep, claim_fingerprint=f"{i:064x}", tool_kind="tool",
                                tool_identifier="refund@payments", contract_digest=C1, bound_at=at(i))
            for i in range(count)
        )
    else:
        DecisionTransition.objects.bulk_create(
            DecisionTransition(deployment=dep, revision=i + 1, from_decision="", to_decision="ready")
            for i in range(count)
        )


_KEYS = {
    "approval-history": ("versions", "version", lambda v: v["version"]),
    "tool-contracts": ("contracts", "contract", lambda c: c["digest"]),
    "tool-contract-bindings": ("bindings", "binding", lambda b: b["claim_fingerprint"]),
    "decision-history": ("transitions", "transition", lambda t: t["revision"]),
}


@pytest.mark.parametrize("route", HISTORY_ROUTES)
def test_each_history_is_bounded_says_so_and_pages_with_an_offset(route):
    viewer = _user("viewer")
    dep = _deployment(viewer)
    size = DeploymentViewSet.APPROVAL_HISTORY_PAGE_SIZE if route == "approval-history" else (
        DeploymentViewSet.HISTORY_PAGE_SIZE
    )
    total = size + 7
    _fill(dep, route, total)
    key, item, ident = _KEYS[route]
    client = _client(viewer)

    first = client.get(_url(dep, route)).json()
    assert (first["returned"], first["truncated"], first[f"{item}_count"], first["page_size"], first["offset"]) == (
        size, True, total, size, 0,
    )
    assert len(first[key]) == size
    second = client.get(_url(dep, route), {"offset": str(size)}).json()
    assert (second["returned"], second["truncated"], second[f"{item}_count"], second["offset"]) == (
        7, False, total, size,
    )
    seen = [ident(row) for row in first[key] + second[key]]
    assert len(set(seen)) == total, "every recorded row once across the pages"
    past = client.get(_url(dep, route), {"offset": str(total)}).json()
    assert (past[key], past["returned"], past["truncated"]) == ([], 0, False)
    furthest = client.get(_url(dep, route), {"offset": str(DeploymentViewSet.HISTORY_MAX_OFFSET)})
    assert furthest.status_code == 200 and furthest.json()["returned"] == 0

    for bad in ("-1", "+1", " 1", "1 ", "1.0", "1e3", "0x10", "１", "", "1_000",
                str(DeploymentViewSet.HISTORY_MAX_OFFSET + 1), "9" * 13):
        refused = client.get(_url(dep, route), {"offset": bad})
        assert refused.status_code == 400, repr(bad)
        assert list(refused.json()) == ["offset"], repr(bad)


def test_the_newest_comes_first_in_every_history():
    viewer = _user("viewer")
    dep = _deployment(viewer)
    client = _client(viewer)
    for route in HISTORY_ROUTES:
        _fill(dep, route, 12)
    versions = client.get(_url(dep, "approval-history")).json()["versions"]
    assert [v["in_force_from"] for v in versions] == [stamp(at(i)) for i in reversed(range(12))]
    contracts = client.get(_url(dep, "tool-contracts")).json()["contracts"]
    assert [c["recorded_at"] for c in contracts] == [stamp(at(i)) for i in reversed(range(12))]
    bindings = client.get(_url(dep, "tool-contract-bindings")).json()["bindings"]
    assert [b["bound_at"] for b in bindings] == [stamp(at(i)) for i in reversed(range(12))]
    transitions = client.get(_url(dep, "decision-history")).json()["transitions"]
    assert [t["revision"] for t in transitions] == list(reversed(range(1, 13)))


_WRITES = ("INSERT", "UPDATE", "DELETE", "REPLACE")


@pytest.mark.parametrize("route", HISTORY_ROUTES)
def test_a_history_read_writes_nothing_and_a_full_page_costs_what_one_row_does(route):
    viewer = _user("viewer")
    dep = _deployment(viewer)
    _tool(dep, "refund@payments")
    client = _client(viewer)
    _fill(dep, route, 1)
    with CaptureQueriesContext(connection) as one:
        assert client.get(_url(dep, route)).status_code == 200
    _fill_more = {"approval-history": 60, "tool-contracts": 120, "tool-contract-bindings": 120,
                  "decision-history": 120}[route]
    other = _deployment(viewer, name="other")
    _fill(other, route, _fill_more)
    with CaptureQueriesContext(connection) as full:
        assert client.get(_url(other, route)).status_code == 200
    statements = [q["sql"] for q in one.captured_queries + full.captured_queries]
    assert not [s for s in statements if s.lstrip().upper().startswith(_WRITES)], statements
    assert len(full.captured_queries) == len(one.captured_queries)


# ------------------------------------------------------- the gate's route, unchanged


def test_the_gates_approval_in_force_route_is_exactly_as_it_was(gate, engine_keyring):
    """Passes on master too: nothing about the gate's route moved."""
    route = DeploymentViewSet.approval_in_force
    assert route.url_path == r"workflows/(?P<workflow>[-a-zA-Z0-9_]{1,200})/approval-in-force"
    assert dict(route.mapping) == {"get": "approval_in_force"}
    assert route.kwargs["authentication_classes"] == [
        gate_approval.GateApprovalAuthentication,
        *api_settings.DEFAULT_AUTHENTICATION_CLASSES,
    ]
    assert route.kwargs["permission_classes"] == [gate_approval.IsGateApprovalReader]
    assert stops.NOT_STOPS["deployment-approval-in-force"].keys() == {"GET"}

    admin = _user("approver", User.Roles.ADMIN)
    dep = _deployment(admin)
    operator = _client(admin)
    put = operator.put(_url(dep, "approved-workflows"), {"workflows": [{"slug": "refund", "name": "Refund"}]},
                       format="json")
    assert put.status_code == 200, put.content
    url = _url(dep, "workflows/refund/approval-in-force")
    assert gate.get(url).status_code == 200
    assert operator.get(url).status_code == 403, "an operator, an admin, is still not the gate"
    assert APIClient().get(url).status_code == 401


@pytest.mark.parametrize("route", HISTORY_ROUTES)
def test_the_gates_credential_reads_none_of_the_histories(gate, route):
    """It is accepted on its own route only; here it is no sign-in at all."""
    dep = _deployment(_user("owner"))
    _record_everything(dep)
    answer = gate.get(_url(dep, route))
    assert answer.status_code == 401
    assert answer.json() == APIClient().get(_url(dep, route)).json()
