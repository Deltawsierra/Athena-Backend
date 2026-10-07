"""Invalidate on a tool-contract change, not only on deployment-wide drift.

The deployment-wide path binds every claim to the inputs its deriver reads and to
the policy in force. Neither sees what a tool registration may DO -- its input and
output schema, its declared effect class -- and the registration's key is stable
while that moves: ``refund@payments`` re-declared with a destructive effect class
is, by name and registry entry, the tool somebody approved. These tests hold that:

- a schema change under an unchanged name, and an effect-class change under an
  unchanged schema, each invalidate EXACTLY the claims bound to that tool: STALE,
  with a retest naming the tool and both digests; a claim bound to another tool
  and an unbound claim do not move;
- no change opens nothing, and re-running opens no duplicate;
- an approval or claim bound to the old contract cannot make a decision READY --
  held live, off the binding and the registration, before any check runs and
  after a re-derive reads the claim back to a pass; an Achilles permit check on a
  workflow whose approval is superseded does not read READY_RESTRICTED;
- the deployment-wide fingerprint path still invalidates every claim as before;
- nothing here holds back a pause or a revocation.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from assurance import composition as comp
from assurance import tool_contract as tc
from assurance.assets import _agent_and_tools
from assurance.claims import apply_claim_transition, derive_claims
from assurance.decision import (
    claim_decision_signal,
    compute_decision,
    decision_support,
    recompute_decision,
)
from assurance.fingerprint import compute_system_fingerprint
from assurance.invalidation import check_invalidations
from assurance.models import (
    ApprovedWorkflow,
    Asset,
    AssuranceClaim,
    Deployment,
    RetestRequirement,
    ToolContract,
    ToolContractBinding,
    ToolContractRewriteRefused,
)
from assurance.revalidation import plan_revalidation
from tests.signed_chains import record_signed

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
D = Deployment.Decision

_PASS = frozenset({Status.SUPPORTED, Status.VERIFIED, Status.PARTIALLY_VERIFIED})

REFUND_SCHEMA = {
    "type": "object",
    "properties": {"customer": {"type": "string"}, "amount": {"type": "number", "maximum": 500}},
    "required": ["customer", "amount"],
}


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _tool(dep, name, identifier, **contract):
    metadata = {"permissions": ["payments:read"], "server": "payments", **contract}
    return Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name=name, identifier=identifier,
        classification=Asset.Classification.APPROVED, metadata=metadata,
    )


def _fresh(dep):
    return Deployment.objects.get(pk=dep.pk)


def _deployment():
    """A scanned deployment with two tools and its three derived claims, all read
    as a pass, and nothing yet bound."""
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    _tool(dep, "refund", "refund@payments", input_schema=REFUND_SCHEMA, effect_class="write")
    _tool(dep, "lookup", "lookup@crm", input_schema={"type": "object"}, effect_class="read")
    derive_claims(_fresh(dep))
    AssuranceClaim.objects.filter(deployment=dep).current().update(status=Status.VERIFIED, confidence=0.9)
    return _fresh(dep)


def _claims(dep):
    return {c.claim_type: c for c in AssuranceClaim.objects.filter(deployment=dep).current()}


def _asset(dep, identifier):
    return Asset.objects.get(deployment=dep, identifier=identifier)


def _redeclare(dep, identifier, **changes):
    asset = _asset(dep, identifier)
    asset.metadata = {**asset.metadata, **changes}
    asset.save(update_fields=["metadata"])
    return asset


def _bound(dep):
    """effective_access bound to refund, ai_bom bound to lookup, data_boundary unbound."""
    claims = _claims(dep)
    tc.bind_claim(claims[ClaimType.EFFECTIVE_ACCESS], _asset(dep, "refund@payments"))
    tc.bind_claim(claims[ClaimType.AI_BOM], _asset(dep, "lookup@crm"))
    return claims


def _open(dep):
    return RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True)


# ---------------------------------------------------------------------------
# The contract and its history
# ---------------------------------------------------------------------------


def test_the_digest_is_the_contract_not_the_name():
    dep = _deployment()
    refund = _asset(dep, "refund@payments")
    before = tc.contract_digest(refund)
    assert len(before) == 64

    # Renaming the tool is not a contract change; nor is the order permissions are listed in.
    refund.name = "Refund (v2)"
    refund.metadata = {**refund.metadata, "permissions": ["payments:read"]}
    assert tc.contract_digest(refund) == before

    for field, value in (
        ("input_schema", {**REFUND_SCHEMA, "required": ["customer"]}),
        ("output_schema", {"type": "object"}),
        ("effect_class", "destructive"),
        ("annotations", {"destructiveHint": True}),
        ("permissions", ["payments:read", "payments:refund"]),
        ("server", "payments-v2"),
    ):
        moved = Asset(kind=refund.kind, identifier=refund.identifier, metadata={**refund.metadata, field: value})
        assert tc.contract_digest(moved) != before, field


def test_the_contract_history_is_appended_never_rewritten():
    dep = _deployment()
    first = tc.record_tool_contracts(dep)
    assert set(first) == {("tool", "refund@payments"), ("tool", "lookup@crm")}
    # Unchanged: nothing appended.
    tc.record_tool_contracts(_fresh(dep))
    assert ToolContract.objects.filter(deployment=dep).count() == 2

    _redeclare(dep, "refund@payments", effect_class="destructive")
    tc.record_tool_contracts(_fresh(dep))
    _redeclare(dep, "refund@payments", effect_class="write")
    tc.record_tool_contracts(_fresh(dep))
    history = list(
        ToolContract.objects.filter(deployment=dep, tool_identifier="refund@payments").order_by("id")
    )
    assert [row.contract["effect_class"] for row in history] == ["write", "destructive", "write"]
    assert history[0].digest == history[2].digest != history[1].digest

    row = history[0]
    row.digest = "0" * 64
    with pytest.raises(ToolContractRewriteRefused):
        row.save()
    with pytest.raises(ToolContractRewriteRefused):
        history[1].delete()


def test_a_declaration_carries_the_schema_and_effect_class_onto_the_registration():
    dep = Deployment.objects.create(name="declared", owner=_admin())
    entry = {
        "name": "refund", "server": "payments", "approved": True, "permissions": ["payments:refund"],
        "inputSchema": REFUND_SCHEMA, "effect_class": " Write ", "annotations": {"destructiveHint": False},
    }
    _agent_and_tools(dep, {"tools": [entry]}, timezone.now())
    tool = _asset(dep, "refund@payments")
    assert tool.metadata["input_schema"] == REFUND_SCHEMA
    assert tool.metadata["effect_class"] == "write"
    assert tool.metadata["annotations"] == {"destructiveHint": False}
    before = tc.contract_digest(tool)

    # Same name, same server, same schema: only the declared effect class moves.
    _agent_and_tools(dep, {"tools": [{**entry, "effect_class": "destructive"}]}, timezone.now())
    tool = _asset(dep, "refund@payments")
    assert tool.metadata["effect_class"] == "destructive"
    assert tc.contract_digest(tool) != before

    # Two lines naming the tool that disagree keep both, never whichever came last.
    _agent_and_tools(
        dep, {"tools": [{**entry, "effect_class": "read"}, {**entry, "effect_class": "destructive"}]},
        timezone.now(),
    )
    assert _asset(dep, "refund@payments").metadata["effect_class"] == {
        "conflicting_declarations": ["destructive", "read"]
    }


def test_only_a_registered_tool_can_be_bound():
    dep = _deployment()
    claims = _claims(dep)
    model = Asset.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt")
    with pytest.raises(ValueError):
        tc.bind_claim(claims[ClaimType.AI_BOM], model)


# ---------------------------------------------------------------------------
# Precise invalidation
# ---------------------------------------------------------------------------


def test_a_schema_change_under_the_same_name_invalidates_exactly_its_dependent_claims():
    dep = _deployment()
    claims = _bound(dep)
    old = tc.contract_digest(_asset(dep, "refund@payments"))
    system_fp = compute_system_fingerprint(_fresh(dep))

    # The schema widens (no amount ceiling). Name, identifier and registry row unchanged.
    wider = {**REFUND_SCHEMA, "properties": {**REFUND_SCHEMA["properties"], "amount": {"type": "number"}}}
    new = tc.contract_digest(_redeclare(dep, "refund@payments", input_schema=wider))
    assert new != old
    # The deployment-wide fingerprint does not see a schema: only the tool path can.
    assert compute_system_fingerprint(_fresh(dep)) == system_fp

    counts = check_invalidations(_fresh(dep))
    assert counts["invalidated"] == 1
    assert counts["retests_opened"] == 1

    after = _claims(dep)
    assert after[ClaimType.EFFECTIVE_ACCESS].status == Status.STALE
    # Bound to another tool, and bound to none: untouched.
    assert after[ClaimType.AI_BOM].status == Status.VERIFIED
    assert after[ClaimType.DATA_BOUNDARY].status == Status.VERIFIED

    [req] = list(_open(dep))
    assert req.claim.fingerprint == claims[ClaimType.EFFECTIVE_ACCESS].fingerprint
    assert "refund@payments" in req.reason
    assert old in req.reason and new in req.reason
    assert "lookup@crm" not in req.reason


def test_an_effect_class_change_with_the_schema_unchanged_invalidates_the_same_way():
    dep = _deployment()
    claims = _bound(dep)
    old = tc.contract_digest(_asset(dep, "lookup@crm"))
    new = tc.contract_digest(_redeclare(dep, "lookup@crm", effect_class="destructive"))
    assert _asset(dep, "lookup@crm").metadata["input_schema"] == {"type": "object"}

    counts = check_invalidations(_fresh(dep))
    assert (counts["invalidated"], counts["retests_opened"]) == (1, 1)

    after = _claims(dep)
    assert after[ClaimType.AI_BOM].status == Status.STALE
    assert after[ClaimType.EFFECTIVE_ACCESS].status == Status.VERIFIED
    assert after[ClaimType.DATA_BOUNDARY].status == Status.VERIFIED
    [req] = list(_open(dep))
    assert req.claim.fingerprint == claims[ClaimType.AI_BOM].fingerprint
    assert "lookup@crm" in req.reason and old in req.reason and new in req.reason


def test_no_change_opens_nothing_and_a_rerun_opens_no_duplicate():
    dep = _deployment()
    _bound(dep)
    assert check_invalidations(_fresh(dep)) == {"invalidated": 0, "retests_opened": 0, "retests_resolved": 0}
    assert not RetestRequirement.objects.filter(deployment=dep).exists()
    assert {c.status for c in _claims(dep).values()} == {Status.VERIFIED}

    _redeclare(dep, "refund@payments", effect_class="destructive")
    assert check_invalidations(_fresh(dep))["retests_opened"] == 1
    events = _claims(dep)[ClaimType.EFFECTIVE_ACCESS].events.count()
    again = check_invalidations(_fresh(dep))
    assert again["retests_opened"] == 0
    assert again["invalidated"] == 1, "still invalidated -- just not opened twice"
    assert _open(dep).count() == 1
    assert _claims(dep)[ClaimType.EFFECTIVE_ACCESS].events.count() == events


def test_a_tool_no_longer_registered_supersedes_what_was_bound_to_it():
    dep = _deployment()
    claims = _bound(dep)
    old = tc.contract_digest(_asset(dep, "refund@payments"))
    _asset(dep, "refund@payments").delete()

    # Removing a component also moves the deployment-wide state, so every claim is
    # invalidated by that path (its reason) -- and the tool's removal is still
    # written on the claim bound to it, with the digest it was bound under.
    check_invalidations(_fresh(dep))
    assert _open(dep).count() == 3
    access = _claims(dep)[ClaimType.EFFECTIVE_ACCESS]
    assert access.status == Status.STALE
    binding = ToolContractBinding.objects.get(claim_fingerprint=claims[ClaimType.EFFECTIVE_ACCESS].fingerprint)
    assert old in binding.invalidation_reason and tc.NOT_REGISTERED in binding.invalidation_reason
    assert any(tc.NOT_REGISTERED in e.note for e in access.events.all())


def test_a_rederive_alone_does_not_answer_the_retest_rebinding_does():
    dep = _deployment()
    claims = _bound(dep)
    _redeclare(dep, "refund@payments", effect_class="destructive")
    check_invalidations(_fresh(dep))

    # The re-derive reads the claim again -- its derivers never read an effect
    # class -- and would answer an ordinary retest. Not this one.
    derive_claims(_fresh(dep))
    assert _open(dep).count() == 1
    signal = claim_decision_signal(_fresh(dep))
    assert [b.tool_identifier for b in signal["superseded_tool_contracts"]] == ["refund@payments"]
    assert signal["cap"] is not None and compute_decision(_fresh(dep)) not in (D.READY, D.READY_RESTRICTED)

    # Re-established against the contract in force, then re-derived: answered.
    binding = tc.bind_claim(_claims(dep)[ClaimType.EFFECTIVE_ACCESS], _asset(dep, "refund@payments"))
    assert binding.contract_digest == tc.contract_digest(_asset(dep, "refund@payments"))
    assert ToolContractBinding.objects.filter(
        claim_fingerprint=claims[ClaimType.EFFECTIVE_ACCESS].fingerprint, released_at__isnull=False
    ).count() == 1
    derive_claims(_fresh(dep))
    assert _open(dep).count() == 0
    assert tc.superseded_bindings(_fresh(dep)) == []


# ---------------------------------------------------------------------------
# READY is held
# ---------------------------------------------------------------------------


def test_a_claim_bound_under_the_old_contract_cannot_make_the_decision_ready():
    dep = _deployment()
    _bound(dep)
    assert compute_decision(_fresh(dep)) == D.READY  # the precondition: ready before the change

    _redeclare(dep, "refund@payments", effect_class="destructive")
    # Held live, before any invalidation check has run.
    signal = claim_decision_signal(_fresh(dep))
    assert signal["cap"] == D.NEEDS_MORE_EVIDENCE
    assert [b.tool_identifier for b in signal["superseded_tool_contracts"]] == ["refund@payments"]
    assert ClaimType.EFFECTIVE_ACCESS not in {c.claim_type for c in signal["supporting"]}
    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE
    assert recompute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE

    support = decision_support(_fresh(dep))
    assert support["decision"] == D.NEEDS_MORE_EVIDENCE
    assert support["claims"]["superseded_tool_contracts"][0]["tool_identifier"] == "refund@payments"
    assert "refund@payments" in support["note"]
    # And the plan says the same claim needs the work.
    plan = plan_revalidation(_fresh(dep))
    assert [w["claim_type"] for w in plan["required"]] == [ClaimType.EFFECTIVE_ACCESS]
    assert "refund@payments" in plan["required"][0]["reason"]

    # A write to the claim row that reads it back to a pass does not lift it.
    AssuranceClaim.objects.filter(deployment=dep).current().update(status=Status.VERIFIED)
    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE


def test_an_approval_under_the_old_contract_does_not_read_as_a_permit(engine_keyring):
    """An Achilles permit check on the approved workflow reads READY_RESTRICTED. The
    same permit check, once the tool the approval covered has a different contract,
    reads nothing better than NEEDS_MORE_EVIDENCE -- until the workflow is approved
    again under the contract in force."""
    dep = Deployment.objects.create(name="permit", owner=_admin())
    refund = _tool(dep, "refund", "refund@payments", input_schema=REFUND_SCHEMA, effect_class="write")
    workflow = ApprovedWorkflow.objects.create(deployment=dep, slug="refund-over-limit", name="refund")
    record_signed(_fresh(dep), "refund-over-limit", comp.HELD, timezone.now() - timedelta(minutes=5))
    tc.bind_workflow(workflow, refund)
    assert compute_decision(_fresh(dep)) == D.READY_RESTRICTED

    _redeclare(dep, "refund@payments", effect_class="destructive")
    assert compute_decision(_fresh(dep)) == D.NEEDS_MORE_EVIDENCE
    counts = check_invalidations(_fresh(dep))
    assert counts["retests_opened"] == 0, "a workflow approval has no claim to retest"
    binding = ToolContractBinding.objects.get(workflow=workflow, released_at__isnull=True)
    assert binding.invalidated_at is not None and "refund@payments" in binding.invalidation_reason

    tc.bind_workflow(workflow, _asset(dep, "refund@payments"))
    assert compute_decision(_fresh(dep)) == D.READY_RESTRICTED


def test_a_change_to_one_tool_holds_nothing_bound_only_to_another():
    dep = _deployment()
    claims = _claims(dep)
    tc.bind_claim(claims[ClaimType.AI_BOM], _asset(dep, "lookup@crm"))
    _redeclare(dep, "refund@payments", effect_class="destructive")
    assert claim_decision_signal(_fresh(dep))["cap"] is None
    assert compute_decision(_fresh(dep)) == D.READY


# ---------------------------------------------------------------------------
# The deployment-wide path is unchanged
# ---------------------------------------------------------------------------


def test_the_deployment_wide_fingerprint_path_still_invalidates_every_claim():
    dep = _deployment()
    _bound(dep)
    before = compute_system_fingerprint(_fresh(dep))
    Asset.objects.create(deployment=dep, kind=Asset.Kind.VECTOR_DB, name="pinecone", identifier="pinecone")
    assert compute_system_fingerprint(_fresh(dep)) != before

    counts = check_invalidations(_fresh(dep))
    assert counts == {"invalidated": 3, "retests_opened": 3, "retests_resolved": 0}
    assert {c.status for c in _claims(dep).values()} == {Status.STALE}
    reasons = [r.reason for r in _open(dep)]
    assert len(reasons) == 3
    assert all("Tool contract changed" not in r for r in reasons), "the deployment-wide reason, as before"


def test_both_changing_at_once_opens_one_retest_per_claim_and_records_the_tool():
    dep = _deployment()
    claims = _bound(dep)
    Asset.objects.create(deployment=dep, kind=Asset.Kind.VECTOR_DB, name="pinecone", identifier="pinecone")
    _redeclare(dep, "refund@payments", effect_class="destructive")

    counts = check_invalidations(_fresh(dep))
    assert counts["invalidated"] == 3 and counts["retests_opened"] == 3
    access = claims[ClaimType.EFFECTIVE_ACCESS]
    assert RetestRequirement.objects.filter(claim__fingerprint=access.fingerprint, resolved_at__isnull=True).count() == 1
    notes = [e.note for e in AssuranceClaim.objects.get(pk=_claims(dep)[ClaimType.EFFECTIVE_ACCESS].pk).events.all()]
    assert any("refund@payments" in n for n in notes)


# ---------------------------------------------------------------------------
# Stops are untouched
# ---------------------------------------------------------------------------


def test_a_pause_stands_over_a_superseded_contract_and_a_check_does_not_lift_it():
    dep = _deployment()
    _bound(dep)
    _redeclare(dep, "refund@payments", effect_class="destructive")
    assert recompute_decision(_fresh(dep), paused=True) == D.PAUSED
    check_invalidations(_fresh(dep))
    recompute_decision(_fresh(dep))
    assert _fresh(dep).decision == D.PAUSED
    assert compute_decision(_fresh(dep), paused=True) == D.PAUSED


def test_a_revocation_of_a_bound_claim_goes_through_and_is_never_invalidated():
    dep = _deployment()
    claims = _bound(dep)
    _redeclare(dep, "refund@payments", effect_class="destructive")
    access = claims[ClaimType.EFFECTIVE_ACCESS]
    apply_claim_transition(access, Status.REVOKED, actor=_admin(), note="withdrawn")
    assert AssuranceClaim.objects.get(pk=access.pk).status == Status.REVOKED

    counts = check_invalidations(_fresh(dep))
    assert counts["invalidated"] == 0 and counts["retests_opened"] == 0
    assert AssuranceClaim.objects.get(pk=access.pk).status == Status.REVOKED
    # A withdrawn claim is no mark against readiness, and neither is its binding.
    assert claim_decision_signal(_fresh(dep))["cap"] is None
