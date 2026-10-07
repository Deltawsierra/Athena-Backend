"""An approval made over HTTP is bound to the contracts of the tools it covers.

The SPINE item reads: "Bind approval to the tool's effective contract (schema +
declared effect class) and invalidate the specific dependent claims when that
contract changes." ``assurance.tool_contract`` holds the invalidation and offers
``bind_workflow``, and until this change nothing in production called it: the
only way to approve a workflow, ``PUT /approved-workflows/``, could not say which
tools the approval covered, so no approval made by a person was ever bound and a
contract change held nothing a person had approved.

Worse, the route re-created every row on every PUT, and a workflow's bindings
cascade with its row: any roster edit -- even renaming the workflow -- shed every
binding, a superseded one included, and lifted the hold a changed contract had put
on the decision.

These tests hold that:

- a workflow entry may name its ``tools``; each is bound to the contract in force
  and read back with the contract it was approved under and the one in force now;
- a contract change under an approval made this way holds the decision, and the
  read says the approval is superseded;
- a roster edit that does not name a workflow's tools keeps them exactly --
  superseded or not -- and re-approves nothing;
- re-approving names the tools again; naming the digest approved is checked
  against the contract in force, so sending a superseded binding back is refused,
  not a silent re-approval;
- a refused approval writes nothing: no roster change, no binding, no release;
- a tool no longer listed is released; a withdrawn workflow takes its bindings;
- the read costs no query per row, and nothing here touches a pause.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import composition as comp
from assurance import tool_contract as tc
from assurance.decision import compute_decision, recompute_decision
from assurance.models import ApprovedWorkflow, Asset, Deployment, ToolContractBinding
from tests.signed_chains import record_signed

pytestmark = pytest.mark.django_db

User = get_user_model()
D = Deployment.Decision

REFUND_SCHEMA = {
    "type": "object",
    "properties": {"customer": {"type": "string"}, "amount": {"type": "number", "maximum": 500}},
    "required": ["customer", "amount"],
}


@pytest.fixture(autouse=True)
def _trusted_engines(engine_keyring):
    return engine_keyring


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


def _fresh(dep):
    return Deployment.objects.get(pk=dep.pk)


def _tool(dep, identifier, **contract):
    metadata = {"permissions": ["payments:read"], "server": "payments", **contract}
    return Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name=identifier.split("@")[0], identifier=identifier,
        classification=Asset.Classification.APPROVED, metadata=metadata,
    )


def _redeclare(dep, identifier, **changes):
    asset = Asset.objects.get(deployment=dep, identifier=identifier)
    asset.metadata = {**asset.metadata, **changes}
    asset.save(update_fields=["metadata"])
    return asset


def _url(dep):
    return f"/api/assurance/deployments/{dep.uuid}/approved-workflows/"


def _entry(slug, tools=None):
    row = {"slug": slug, "name": slug.replace("-", " ").title()}
    if tools is not None:
        row["tools"] = tools
    return row


def _refund(digest=None):
    entry = {"kind": "tool", "identifier": "refund@payments"}
    if digest is not None:
        entry["contract_digest"] = digest
    return entry


def _put(client, dep, *rows):
    return client.put(_url(dep), {"workflows": list(rows)}, format="json")


def _setup():
    """A deployment with two tools, and a signed, held run of `refund-over-limit`."""
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    _tool(dep, "refund@payments", input_schema=REFUND_SCHEMA, effect_class="write")
    _tool(dep, "lookup@crm", input_schema={"type": "object"}, effect_class="read")
    record_signed(_fresh(dep), "refund-over-limit", comp.HELD, timezone.now() - timedelta(minutes=5))
    return dep, _client(dep.owner)


def _live(dep):
    return list(
        ToolContractBinding.objects.filter(deployment=dep, released_at__isnull=True)
        .order_by("tool_identifier")
        .values_list("workflow__slug", "tool_identifier", "contract_digest")
    )


def _digest(dep, identifier):
    return tc.contract_digest(Asset.objects.get(deployment=dep, identifier=identifier))


# --------------------------------------------------------------------------
# The approval binds, and the read says under which contract.
# --------------------------------------------------------------------------


def test_an_approval_names_its_tools_and_each_is_bound_to_the_contract_in_force():
    dep, client = _setup()
    response = _put(client, dep, _entry("refund-over-limit", [_refund()]))
    assert response.status_code == 200, response.data

    refund = _digest(dep, "refund@payments")
    assert _live(dep) == [("refund-over-limit", "refund@payments", refund)]
    row = response.data["approved"][0]
    assert len(row["tools"]) == 1
    tool = row["tools"][0]
    assert set(tool) == {"kind", "identifier", "contract_digest", "bound_at", "current_digest", "superseded"}
    assert tool["kind"] == "tool" and tool["identifier"] == "refund@payments"
    assert tool["contract_digest"] == tool["current_digest"] == refund
    assert tool["superseded"] is False
    assert compute_decision(_fresh(dep)) == D.READY_RESTRICTED


def test_a_contract_change_under_an_http_approval_holds_the_decision():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    before = _digest(dep, "refund@payments")

    _redeclare(dep, "refund@payments", effect_class="destructive")
    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE

    tool = client.get(_url(dep)).data["approved"][0]["tools"][0]
    assert tool["contract_digest"] == before
    assert tool["current_digest"] == _digest(dep, "refund@payments") != before
    assert tool["superseded"] is True


def test_a_tool_no_longer_registered_reads_superseded_with_no_contract_in_force():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    Asset.objects.filter(deployment=dep, identifier="refund@payments").delete()

    tool = client.get(_url(dep)).data["approved"][0]["tools"][0]
    assert tool["current_digest"] is None and tool["superseded"] is True
    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE


# --------------------------------------------------------------------------
# A roster edit is not a re-approval.
# --------------------------------------------------------------------------


def test_a_roster_edit_keeps_a_superseded_approval_holding():
    """Fails on master: the PUT deleted and re-created every row, the binding
    cascaded with it, and the decision went back to READY_RESTRICTED."""
    dep, client = _setup()
    workflow = ApprovedWorkflow.objects.create(deployment=dep, slug="refund-over-limit", name="refund")
    tc.bind_workflow(workflow, Asset.objects.get(deployment=dep, identifier="refund@payments"))
    assert compute_decision(_fresh(dep)) == D.READY_RESTRICTED
    _redeclare(dep, "refund@payments", effect_class="destructive")
    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE

    # Re-declare the same workflow, renamed, without naming its tools: a roster
    # edit, not a re-approval. On master this read READY_RESTRICTED again.
    response = _put(client, dep, {"slug": "refund-over-limit", "name": "Refunds"})
    assert response.status_code == 200, response.data

    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE
    assert ApprovedWorkflow.objects.get(deployment=dep, slug="refund-over-limit").pk == workflow.pk
    assert ToolContractBinding.objects.filter(workflow=workflow, released_at__isnull=True).count() == 1
    assert response.data["approved"][0]["tools"][0]["superseded"] is True


def test_a_roster_edit_moves_the_declaration_but_not_the_tool_approval():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    bound = ToolContractBinding.objects.get(deployment=dep, released_at__isnull=True)
    second = _admin()

    _put(_client(second), dep, {"slug": "refund-over-limit", "name": "Refunds", "description": "renamed"})
    row = ApprovedWorkflow.objects.get(deployment=dep, slug="refund-over-limit")
    assert (row.name, row.description, row.approved_by_id) == ("Refunds", "renamed", second.pk)
    again = ToolContractBinding.objects.get(deployment=dep, released_at__isnull=True)
    assert (again.pk, again.bound_by_id, again.bound_at) == (bound.pk, bound.bound_by_id, bound.bound_at)


def test_naming_the_same_tools_under_an_unchanged_contract_writes_no_binding():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    _put(client, dep, _entry("refund-over-limit", [_refund(_digest(dep, "refund@payments"))]))
    assert ToolContractBinding.objects.filter(deployment=dep).count() == 1


# --------------------------------------------------------------------------
# Re-approval is explicit, and checked.
# --------------------------------------------------------------------------


def test_re_approving_under_the_contract_in_force_lifts_the_hold():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    _redeclare(dep, "refund@payments", effect_class="destructive")
    now = _digest(dep, "refund@payments")

    response = _put(client, dep, _entry("refund-over-limit", [_refund(now)]))
    assert response.status_code == 200, response.data
    assert response.data["approved"][0]["tools"][0]["superseded"] is False
    assert compute_decision(_fresh(dep)) == D.READY_RESTRICTED
    # The old approval is kept, released -- the record of what was approved before.
    assert ToolContractBinding.objects.filter(deployment=dep, released_at__isnull=False).count() == 1


def test_sending_a_superseded_approval_back_is_refused_and_writes_nothing():
    """A client that reads the set and PUTs it back sends the digest it was
    approved under. That must not re-approve a contract change nobody looked at."""
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    _redeclare(dep, "refund@payments", effect_class="destructive")
    read = client.get(_url(dep)).data["approved"][0]
    before = _live(dep)

    response = _put(
        client,
        dep,
        _entry("refund-over-limit", [{k: read["tools"][0][k] for k in ("kind", "identifier", "contract_digest")}]),
        _entry("new-workflow"),
    )
    assert response.status_code == 400
    why = response.data["workflows"][0]["tools"][0][0]
    assert "contract in force" in why
    assert _digest(dep, "refund@payments") in why
    # Nothing written: no new workflow, the same live binding, still held.
    assert set(ApprovedWorkflow.objects.filter(deployment=dep).values_list("slug", flat=True)) == {
        "refund-over-limit"
    }
    assert _live(dep) == before
    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE


@pytest.mark.parametrize(
    "tools, fragment",
    [
        ([{"kind": "tool", "identifier": "nope@nowhere"}], "is registered"),
        ([_refund(), _refund()], "listed twice"),
    ],
)
def test_an_approval_naming_a_tool_it_cannot_bind_writes_nothing(tools, fragment):
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [{"kind": "tool", "identifier": "lookup@crm"}]))
    before = _live(dep)

    response = _put(client, dep, _entry("refund-over-limit", tools), _entry("new-workflow"))
    assert response.status_code == 400
    errors = response.data["workflows"][0]["tools"]
    assert any(fragment in msg for msgs in errors.values() for msg in msgs)
    assert _live(dep) == before, "a refused approval released or bound something"
    assert not ApprovedWorkflow.objects.filter(deployment=dep, slug="new-workflow").exists()


@pytest.mark.parametrize(
    "entry",
    [
        {"kind": "agent", "identifier": "refund@payments"},
        {"kind": "tool", "identifier": "refund@payments", "contract_digest": "not-a-digest"},
        {"kind": "tool"},
    ],
)
def test_a_malformed_tool_entry_is_a_400(entry):
    dep, client = _setup()
    response = _put(client, dep, _entry("refund-over-limit", [entry]))
    assert response.status_code == 400
    assert not ApprovedWorkflow.objects.filter(deployment=dep).exists()


def test_too_many_tools_for_one_workflow_is_refused():
    dep, client = _setup()
    tools = [{"kind": "tool", "identifier": f"t{i}@x"} for i in range(tc.MAX_TOOLS_PER_WORKFLOW + 1)]
    response = _put(client, dep, _entry("refund-over-limit", tools))
    assert response.status_code == 400
    assert "more than the" in str(response.data)


# --------------------------------------------------------------------------
# Leaving.
# --------------------------------------------------------------------------


def test_a_tool_left_out_of_the_list_is_released_and_an_empty_list_releases_all():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund(), {"kind": "tool", "identifier": "lookup@crm"}]))
    assert [b[1] for b in _live(dep)] == ["lookup@crm", "refund@payments"]

    _put(client, dep, _entry("refund-over-limit", [{"kind": "tool", "identifier": "lookup@crm"}]))
    assert [b[1] for b in _live(dep)] == ["lookup@crm"]

    _put(client, dep, _entry("refund-over-limit", []))
    assert _live(dep) == []
    assert ToolContractBinding.objects.filter(deployment=dep).count() == 2, "released, not deleted"


def test_a_withdrawn_workflow_takes_its_bindings_with_it():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]), _entry("other"))
    _redeclare(dep, "refund@payments", effect_class="destructive")

    _put(client, dep, _entry("other"))
    assert not ToolContractBinding.objects.filter(deployment=dep).exists()


# --------------------------------------------------------------------------
# Cost, and the stops.
# --------------------------------------------------------------------------


def test_reading_approved_tools_does_not_cost_a_query_per_row():
    dep, client = _setup()
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    with CaptureQueriesContext(connection) as few:
        client.get(_url(dep))

    rows = [_entry(f"wf-{n}", [_refund(), {"kind": "tool", "identifier": "lookup@crm"}]) for n in range(20)]
    _put(client, dep, _entry("refund-over-limit", [_refund()]), *rows)
    with CaptureQueriesContext(connection) as many:
        client.get(_url(dep))
    assert len(many) == len(few), f"{len(few)} queries for 1 row, {len(many)} for 21"


def test_an_approval_does_not_lift_a_pause():
    dep, client = _setup()
    assert recompute_decision(_fresh(dep), paused=True) == D.PAUSED
    _put(client, dep, _entry("refund-over-limit", [_refund()]))
    assert _fresh(dep).decision == D.PAUSED
    assert compute_decision(_fresh(dep), paused=True) == D.PAUSED


def test_a_viewer_cannot_approve_tools():
    dep, _ = _setup()
    viewer = User.objects.create_user(username="viewer", password="x", role=User.Roles.VIEWER)
    dep.owner = viewer
    dep.save(update_fields=["owner"])
    response = _put(_client(viewer), dep, _entry("refund-over-limit", [_refund()]))
    assert response.status_code == 403
    assert not ToolContractBinding.objects.filter(deployment=dep).exists()
