"""SPINE's recovery record (SP-1): one per incident, each step derived from its witnesses.

An incident (a finding) had no recovery record at all: nothing said how far its recovery
had got, on what, or what was still uncertain. :mod:`assurance.recovery_record` keeps one:
each step a ``mythos_core.status.Recovery`` whose state is derived from what it rests on
-- the evidence, the Action Gate permits and reconciliation receipts, the repair contract,
the closure evidence, the owner's acceptance -- each resolved in the finding's own
deployment, and never typed in. A declared coverage gap (``mythos_core.coverage``) never
yields a recovered state: the step reads ``AUDIT_INCOMPLETE`` and names the gap. The
history is append-only (the #206 refusals are in
``tests/test_no_history_row_is_rewritten_past_its_guard.py``).

On master there is no recovery record, so every test here fails there.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import outcome as oc
from mythos_core import status as st

from assurance import recovery_record as rr
from assurance.models import (
    ClaimEvidence,
    Deployment,
    Evidence,
    Finding,
    RecoveryRecord,
    RecoveryRecordRewriteRefused,
    Unknown,
)
from assurance.retest_closure import INCOMPLETE_REPAIR, INCOMPLETE_REPAIR_PATTERNS, record_closure_evidence
from tests.repair_contracts import agree, replay
from tests.signed_chains import record_reconciliation, record_signed

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
WF = "refund"
T0, T1 = "2026-11-01T00:00:00.000000Z", "2026-11-02T00:00:00.000000Z"
COVERED = {
    "sources": [{"source": "edr", "kind": "log", "start": T0, "end": T1}],
    "observations": [{"source": "edr", "start": T0, "end": T1, "basis": "observed"}],
}
GAP = {**COVERED, "gaps": [{"kind": "failed_collector", "subject": "edr-west"}]}
COMPLETE = {
    "vulnerable": {"ran": True, "outcome": "failed"},
    "repaired": {"ran": True, "outcome": "passed"},
    "benign": {"ran": True, "outcome": "passed"},
    INCOMPLETE_REPAIR: {p: {"ran": True, "outcome": "failed"} for p in INCOMPLETE_REPAIR_PATTERNS},
}


def _until():
    return timezone.now() + timedelta(days=30)


def _incident(name="d", *, owner=True):
    person = User.objects.create_user(username=f"owner-{name}", password="x", role=User.Roles.ADMIN) if owner else None
    dep = Deployment.objects.create(name=name, owner=person)
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{name}", finding_type="sql_injection", title="SQLi", severity="critical",
        retest_required=True,
    )


def _repaired_and_tested(finding):
    """The repair agreed, then a retest the closure gate would close on."""
    agree(finding)
    return record_closure_evidence(
        finding, fixtures=copy.deepcopy(COMPLETE), origin=ClaimEvidence.Origin.INDEPENDENT,
        content_digest="sha256:ab12", document=replay(finding, COMPLETE),
    )


def _permit(dep):
    return record_signed(dep, WF, oc.HELD, datetime.now(UTC) - timedelta(minutes=2)).outcome_id


def _states(steps):
    return [step.state for step in steps]


def _witnesses(step, condition):
    return [c["witness"] for c in step.conditions if c["condition"] == condition]


def _history(finding):
    return list(RecoveryRecord._base_manager.filter(finding=finding).order_by("version").values())


# -------------------------------------------------- the state is derived, step by step


def test_a_recovery_starts_under_investigation_on_the_incident_alone():
    finding = _incident()
    (step,) = rr.record(finding)
    assert (step.version, step.state, step.reopens, step.release) == (1, st.UNDER_INVESTIGATION, "", st.FAIL)
    assert step.conditions == [{"condition": "incident_recorded", "witness": {"kind": "finding", "ref": str(finding.uuid)}}]
    # Coverage of nothing is not full coverage, and the record says so with its source.
    assert {"statement": "coverage:no_required_source", "sources": [{"kind": "coverage", "ref": f"finding:{finding.uuid}"}]} in (
        step.residual_uncertainty
    )


def test_each_step_follows_the_last_as_s1_allows_and_names_its_witnesses():
    finding = _incident()
    closure = _repaired_and_tested(finding)
    owner = finding.deployment.owner

    steps = rr.record(finding, by=owner, body={"coverage": COVERED}, accept_until=_until())

    assert _states(steps) == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED, st.RECOVERY_ACCEPTED]
    assert [s.version for s in steps] == [1, 2, 3, 4]
    accepted = steps[-1]
    contract = finding.repair_contracts.get()
    assert _witnesses(accepted, "repair_agreed") == [{"kind": "repair_contract", "ref": str(contract.uuid)}]
    assert _witnesses(accepted, "repair_tested") == [{"kind": "closure_evidence", "ref": str(closure.uuid)}]
    assert _witnesses(accepted, "owner_accepted") == [{"kind": "owner", "ref": f"user:{owner.pk}"}]
    assert accepted.release == st.PASS and accepted.accepted_by == owner
    # Each step is the one S1 lets follow the one before, and only the last passes.
    for before, after in zip(steps, steps[1:], strict=False):
        st.check_recovery_step(rr._as_recovery(before), rr._as_recovery(after))
    assert [s.release for s in steps[:-1]] == [st.FAIL] * 3
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner)
    assert refused.value.code == "terminal"


def test_a_declared_coverage_gap_never_yields_a_recovered_state_and_reads_audit_incomplete():
    finding = _incident()
    _repaired_and_tested(finding)
    owner = finding.deployment.owner

    steps = rr.record(finding, by=owner, body={"coverage": GAP}, accept_until=_until())

    assert _states(steps) == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    held = steps[-1]
    assert held.release == st.AUDIT_INCOMPLETE
    assert "coverage:failed_collector:edr-west" in held.gaps
    assert not RecoveryRecord.objects.filter(finding=finding, state__in=sorted(rr.RECOVERED)).exists()
    # Once the gap is gone the next step is the acceptance, and it passes.
    (accepted,) = rr.record(finding, by=owner, body={"coverage": COVERED}, accept_until=_until())
    assert (accepted.state, accepted.release) == (st.RECOVERY_ACCEPTED, st.PASS)


def test_a_gap_also_holds_back_restored_with_restrictions():
    finding = _incident()
    _repaired_and_tested(finding)
    dep = finding.deployment
    permit = _permit(dep)
    receipt = record_reconciliation(dep, WF, permit, "applied").receipt_id
    body = {"permits": [permit], "receipts": [receipt], "restrictions": ["refunds-manual-only"]}

    held = rr.record(finding, body={**body, "coverage": GAP})[-1]
    assert (held.state, held.release) == (st.REPAIR_TESTED, st.AUDIT_INCOMPLETE)
    assert "coverage:failed_collector:edr-west" in held.gaps

    (restored,) = rr.record(finding, body={"coverage": COVERED})
    assert restored.state == st.RESTORED_WITH_RESTRICTIONS and restored.restrictions == ["refunds-manual-only"]
    assert _witnesses(restored, "effect_read_back") == [{"kind": "receipt", "ref": receipt}]
    assert _witnesses(restored, "effect_permitted") == [{"kind": "permit", "ref": permit}]
    assert restored.release == st.FAIL, "restored is not accepted: only an accepted recovery passes"


def test_a_failed_readback_is_a_blocker_and_a_reopen_names_what_it_reopens():
    finding = _incident()
    dep = finding.deployment
    permit = _permit(dep)
    failed = record_reconciliation(dep, WF, permit, "not_applied").receipt_id
    agree(finding)

    blocked = rr.record(finding, body={"permits": [permit], "receipts": [failed]})[-1]
    assert blocked.state == st.RECOVERY_INCOMPLETE
    assert blocked.gaps == [f"effect_not_applied:receipt:{failed}"]

    applied = record_reconciliation(dep, WF, permit, "applied").receipt_id
    proposed = rr.record(finding, body={"receipts": [applied]})
    # After a blocker, S1 lets only a repair proposed (or a reopen) follow, never acceptance.
    assert _states(proposed) == [st.REPAIR_PROPOSED]
    # A containment whose receipt and gaps are no longer linked has lost its support:
    # nothing else may follow it, so it is reopened, and the reopen names it.
    second = _incident("second")
    gate = _permit(second.deployment)
    readback = record_reconciliation(second.deployment, WF, gate, "applied").receipt_id
    first = rr.record(second, body={"permits": [gate], "receipts": [readback], "gaps": ["edr-west-offline"]})
    assert _states(first) == [st.UNDER_INVESTIGATION, st.CONTAINED_WITH_GAPS]
    (reopened,) = rr.record(second, body={"receipts": [], "gaps": []})
    assert (reopened.state, reopened.reopens) == (st.UNDER_INVESTIGATION, str(first[-1].uuid))


def test_a_step_that_moves_nothing_is_refused_with_its_reason():
    finding = _incident()
    rr.record(finding)
    evidence = Evidence.objects.create(finding=finding, classification="technically_verified")
    for body in ({}, {"evidence": [str(evidence.uuid)]}):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, body=body)
        assert refused.value.code == "nothing_moved"
        assert "under_investigation" in str(refused.value)
    assert RecoveryRecord.objects.filter(finding=finding).count() == 1


# --------------------------------------------------------- never typed in (M1)


@pytest.mark.parametrize("field", ["state", "conditions", "release", "accepted_by"])
def test_a_derived_field_posted_is_refused_and_records_nothing(field):
    finding = _incident()
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, body={field: st.RECOVERY_ACCEPTED})
    assert refused.value.code == "not_posted" and "derived" in str(refused.value)
    assert _history(finding) == []


def test_a_state_set_by_hand_is_refused_at_save():
    finding = _incident()
    links, coverage = rr.resolve(finding)
    for typed in (
        {"state": st.RECOVERY_ACCEPTED},
        {"release": st.PASS},
        {"conditions": []},
        {"residual_uncertainty": []},
        {"gaps": ["none"]},
    ):
        row = rr.draft(finding, version=1, links=links, coverage=coverage)
        for name, value in typed.items():
            setattr(row, name, value)
        with pytest.raises(rr.RecoveryRefused) as refused:
            row.save()
        assert refused.value.code == "not_derived", typed
    with pytest.raises(rr.RecoveryRefused):
        RecoveryRecord.objects.create(
            finding=finding, version=1, state=st.RECOVERY_ACCEPTED, release=st.PASS, links=links, coverage=coverage
        )
    assert _history(finding) == []
    # The step drafted as derived saves.
    rr.draft(finding, version=1, links=links, coverage=coverage).save()
    assert len(_history(finding)) == 1


# ------------------------------------------------------- append-only history (M3)


def test_a_recorded_step_is_never_rewritten_or_deleted():
    finding = _incident()
    (step,) = rr.record(finding)
    before = _history(finding)
    with pytest.raises(RecoveryRecordRewriteRefused):
        step.save()
    with pytest.raises(RecoveryRecordRewriteRefused):
        step.save(update_fields=["recorded_at"])
    with pytest.raises(RecoveryRecordRewriteRefused):
        step.delete()
    with pytest.raises(RecoveryRecordRewriteRefused):
        RecoveryRecord.objects.filter(pk=step.pk).update(state=st.RECOVERY_ACCEPTED)
    with pytest.raises(RecoveryRecordRewriteRefused):
        RecoveryRecord.objects.filter(pk=step.pk).delete()
    assert _history(finding) == before


# ----------------------------------------------- links stay in one deployment (M4)


def _elsewhere(kind):
    other = _incident("elsewhere")
    if kind == "evidence":
        return {"evidence": [str(Evidence.objects.create(finding=other, classification="technically_verified").uuid)]}
    permit = _permit(other.deployment)
    if kind == "permits":
        return {"permits": [permit]}
    return {"receipts": [record_reconciliation(other.deployment, WF, permit, "applied").receipt_id]}


@pytest.mark.parametrize("kind", ["evidence", "permits", "receipts"])
def test_a_link_to_another_deployments_record_is_refused(kind):
    finding = _incident()
    body = _elsewhere(kind)
    if kind == "receipts":
        # Its permit is linked too, so the receipt is refused for whose it is, not for that.
        body["permits"] = [_permit(finding.deployment)]
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, body=body)
    assert refused.value.code == "unknown_link", refused.value
    assert "this deployment" in str(refused.value)
    assert _history(finding) == []


def test_the_deployments_own_links_are_taken_and_a_permit_must_be_a_signed_gate_decision():
    finding = _incident()
    dep = finding.deployment
    evidence = Evidence.objects.create(finding=finding, classification="technically_verified")
    permit = _permit(dep)
    (step,) = rr.record(finding, body={"evidence": [str(evidence.uuid)], "permits": [permit]})
    assert _witnesses(step, "evidence_linked") == [{"kind": "evidence", "ref": str(evidence.uuid)}]
    assert _witnesses(step, "effect_permitted") == [{"kind": "permit", "ref": permit}]
    athena = record_signed(dep, WF, oc.HELD, datetime.now(UTC) - timedelta(minutes=2), engine="athena").outcome_id
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, body={"permits": [athena]})
    assert refused.value.code == "not_a_permit"


# ------------------------------------------- residual uncertainty, with sources (M6)


def test_residual_uncertainty_carries_every_item_with_its_sources():
    finding = _incident()
    evidence = Evidence.objects.create(finding=finding, classification="vendor_asserted")
    gap = Unknown.objects.create(
        deployment=finding.deployment, finding=finding, fingerprint="u1", question="was the backup restored clean?"
    )
    said = {"statement": "the vendor's log covers only one region", "sources": [{"kind": "evidence", "ref": str(evidence.uuid)}]}

    (step,) = rr.record(finding, body={"evidence": [str(evidence.uuid)], "residual_uncertainty": [said], "coverage": GAP})

    residual = step.residual_uncertainty
    assert {"statement": gap.question, "sources": [{"kind": "unknown", "ref": str(gap.uuid)}]} in residual
    assert said in residual
    assert {"statement": "coverage:failed_collector:edr-west", "sources": [{"kind": "coverage", "ref": f"finding:{finding.uuid}"}]} in (
        residual
    )
    assert RecoveryRecord.objects.get(pk=step.pk).residual_uncertainty == residual
    for bad, code in (
        ({"statement": "x", "sources": []}, "unsourced_uncertainty"),
        ({"statement": "x", "sources": [{"kind": "evidence", "ref": "not-linked"}]}, "unknown_source"),
    ):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, body={"residual_uncertainty": [bad]})
        assert refused.value.code == code


# ---------------------------------------------------- the owner's acceptance (D4)


def test_only_the_deployments_owner_accepts_and_none_without_an_owner():
    finding = _incident()
    _repaired_and_tested(finding)
    someone = User.objects.create_user(username="another-admin", password="x", role=User.Roles.ADMIN)
    for by, until, code in (
        (someone, _until(), "not_the_owner"),
        (None, _until(), "not_the_owner"),
        (finding.deployment.owner, timezone.now() - timedelta(seconds=1), "acceptance_ended"),
    ):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, by=by, body={"coverage": COVERED}, accept_until=until)
        assert refused.value.code == code
    unowned = _incident("unowned", owner=False)
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(unowned, by=someone, accept_until=_until())
    assert (refused.value.code, str(refused.value)) == ("no_owner", "no owner set for this deployment")
    assert _history(finding) == [] and _history(unowned) == []
