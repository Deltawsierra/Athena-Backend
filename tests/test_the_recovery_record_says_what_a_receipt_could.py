"""SPINE SP-4, part 2a: the recovery record says only what a recovery receipt could say.

Mythos-Core#82 defines the recovery receipt (``mythos_core.recovery_receipt``,
``mythos.recovery-receipt/v1``): one signed statement of what an incident's recovery
record said at one instant. Before Athena-Backend can issue one, its own record
(:mod:`assurance.recovery_record`) has to say only what a receipt could say. It did not:

- an acceptance that had ended still read ``recovery_accepted`` and ``PASS``: the record
  compared ``accepted_until`` with the step's own ``recorded_at``, never the reader's
  instant;
- a ``PASS`` could sit beside listed gaps (posted gaps were carried to an accepted step);
- the release was this backend's own arithmetic, not the core's ``release_status``;
- nothing recorded who vouches for each witness;
- restrictions and posted gaps were free text, where a receipt takes names.

Each test below holds one of those to the core: its vectors (``tests/vectors/
recovery-receipt-v1.json``, the core's own file at the pinned commit, byte for byte: the
core does not install them), its release rule, its standings and its sentences. The last
tests build, sign and verify a real receipt of the record's own steps with the vectors'
test key, so "could say" is asked of the core itself.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import re
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import outcome as oc
from mythos_core import recovery_receipt as core
from mythos_core import scope as core_scope
from mythos_core import status as st
from rest_framework.test import APIClient

from assurance import incident_scope as scope
from assurance import recovery_record as rr
from assurance.models import IncidentScopeRevision, RecoveryRecord
from safety import degraded, stops
from tests import incident_scopes as scopes
from tests.incident_scopes import declare as declare_scope
from tests.repair_contracts import agree
from tests.signed_chains import ENGINE_KEYS, record_reconciliation
from tests.test_a_recovery_record_is_derived_from_its_witnesses import (
    COVERED,
    GAP,
    WF,
    _history,
    _incident,
    _permit,
    _repaired_and_tested,
    _states,
    _until,
)

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
VECTORS = Path(__file__).resolve().parent / "vectors" / "recovery-receipt-v1.json"
#: Byte for byte Mythos-Core's tests/vectors/recovery-receipt-v1.json at 12c6433.
VECTOR_SHA256 = "f0f429b50a2a5cfdd34d093498794bbad66a28ffe5ead6909f1cd6a51358c319"
#: The words no recovery receipt says, and so nothing here (``mythos_core.recovery_receipt``).
REASSURANCE = {"clean", "resolved", "secure", "safe"}


def _vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _key() -> Ed25519PrivateKey:
    """The vectors' recovery-receipt test key: the private seed is the SHA-256 of its phrase."""
    phrase = _vectors()["keys"]["recovery-receipt"]["phrase"]
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(phrase.encode()).digest())


def _read(finding):
    return rr.finding_record(finding)


def _row(step) -> RecoveryRecord:
    return RecoveryRecord._base_manager.get(uuid=step["ref"])


def _at(monkeypatch, instant):
    """Make the server's clock read ``instant``."""
    monkeypatch.setattr(timezone, "now", lambda: instant)


def _accepted(finding, *, by=None, body=None, until=None):
    """``finding``'s recovery accepted by its owner under a declared scope, every witness linked."""
    declare_scope(finding)
    _repaired_and_tested(finding)
    owner = finding.deployment.owner
    steps = rr.record(
        finding, by=by or owner, body={"coverage": COVERED, **(body or {})}, accept_until=until or _until()
    )
    return steps


def _signed_links(finding):
    """A permit and the receipt that reads its effect back, both of the finding's deployment."""
    dep = finding.deployment
    permit = _permit(dep)
    return permit, record_reconciliation(dep, WF, permit, "applied").receipt_id


def _words(text) -> set[str]:
    return set(re.split(r"[^a-z]+", str(text).lower()))


# --------------------------------------------------------- the core's vectors, as carried


def test_the_vectors_are_the_cores_own_file_and_name_the_cores_words():
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == VECTOR_SHA256
    v = _vectors()
    assert (v["receipt_schema"], v["role"]) == (core.RECEIPT_SCHEMA, core.RECOVERY_RECEIPT_ROLE)
    assert tuple(v["sets"]["standings"]) == core.RECEIPT_STANDINGS
    assert tuple(v["sets"]["recovered_states"]) == core.RECOVERED_STATES
    assert tuple(v["sets"]["vouchers"]) == core.VOUCHERS
    assert v["voucher_words"] == {voucher: core.voucher_words(voucher) for voucher in core.VOUCHERS}
    assert v["keys"]["recovery-receipt"]["key_id"] == oc.key_id_for(oc.raw_public_key(_key()))


# ------------------------------------------------------------ 1. the release is the core's


def test_the_release_is_the_cores_rule_over_every_case_of_its_status_rule():
    """Every state, held back from each recovered state and from none, with a gap and with
    none: the record's release (:func:`recovery_record.release_of`) gives the core's answer,
    or is refused under the core's code."""
    cases = _vectors()["status_rule"]
    assert len(cases) == 42
    for case in cases:
        asked = dict(
            state=case["state"], gaps=["a-gap"] if case["gap"] else [], held_back_from=case["held_back_from"],
            acceptance_carries=case["state"] == st.RECOVERY_ACCEPTED,
        )
        if case.get("refused") in st.RECOVERY_REFUSALS:
            # S1's own rule (a state that names its gaps), which the record asks before any
            # release: derive builds the step as a ``status.Recovery`` first.
            with pytest.raises(st.RecoveryError) as refused:
                st.Recovery(ref="step", state=case["state"], conditions=("incident_recorded:finding:f",), gaps=())
            assert refused.value.code == case["refused"], case
        elif "refused" in case:
            with pytest.raises(rr.RecoveryRefused) as refused:
                rr.release_of(**asked)
            assert refused.value.code == case["refused"], case
        else:
            assert rr.release_of(**asked) == case["release"], case


def _scenarios(monkeypatch) -> dict:
    """One incident of each shape the record can take, recorded through ``record`` and
    read through ``finding_record``: by name, the finding."""
    out = {}

    out["accepted"] = _incident("accepted")
    _accepted(out["accepted"])

    out["accepted with a posted gap"] = _incident("posted-gap")
    _accepted(out["accepted with a posted gap"], body={"gaps": ["edr-west-offline"]})

    out["held back from acceptance by coverage"] = _incident("held-accept")
    declare_scope(out["held back from acceptance by coverage"])
    _repaired_and_tested(out["held back from acceptance by coverage"])
    finding = out["held back from acceptance by coverage"]
    rr.record(finding, by=finding.deployment.owner, body={"coverage": GAP}, accept_until=_until())

    out["held back from a restore by coverage"] = finding = _incident("held-restore")
    declare_scope(finding)
    _repaired_and_tested(finding)
    permit, receipt = _signed_links(finding)
    admin = User.objects.create_user(username="scenario-admin", password="x", role=User.Roles.ADMIN)
    rr.record(finding, by=admin, body={"permits": [permit], "receipts": [receipt], "restrictions": ["manual-only"],
                                       "coverage": GAP})

    out["held back for want of a scope"] = finding = _incident("no-scope")
    _repaired_and_tested(finding)
    rr.record(finding, by=finding.deployment.owner, body={"coverage": COVERED}, accept_until=_until())

    out["restored"] = finding = _incident("restored")
    declare_scope(finding)
    _repaired_and_tested(finding)
    permit, receipt = _signed_links(finding)
    rr.record(finding, by=admin, body={"permits": [permit], "receipts": [receipt], "restrictions": ["manual-only"],
                                       "coverage": COVERED})

    out["contained"] = finding = _incident("contained")
    permit, receipt = _signed_links(finding)
    rr.record(finding, by=admin, body={"permits": [permit], "receipts": [receipt], "gaps": ["edr-west-offline"]})

    out["blocked"] = finding = _incident("blocked")
    permit = _permit(finding.deployment)
    failed = record_reconciliation(finding.deployment, WF, permit, "not_applied").receipt_id
    rr.record(finding, by=admin, body={"permits": [permit], "receipts": [failed]})

    out["accepted, then a wider scope"] = finding = _incident("wider")
    primary = scopes.asset(finding.deployment, "primary-route")
    _accepted_under(finding, primary)
    declare_scope(finding, primary, scopes.asset(finding.deployment, "backup-route"))

    out["stored with no recorder"] = finding = _incident("nobody")
    _stored_with_no_recorder(finding)
    return out


def _stored_with_no_recorder(finding, body=None):
    """A step stored with no recorder: ``record`` refuses one, so only a row written before
    that refusal, or drafted directly, can be one. Saved through every check of the model."""
    links, coverage = rr.resolve(finding, body)
    row = rr.draft(finding, version=1, links=links, coverage=coverage)
    row.save()
    return row


def _accepted_under(finding, *records):
    declare_scope(finding, *records)
    _repaired_and_tested(finding)
    return rr.record(finding, by=finding.deployment.owner, body={"coverage": COVERED}, accept_until=_until())


def _carries(state) -> bool:
    return state == st.RECOVERY_ACCEPTED


def test_every_step_recorded_and_read_gives_the_cores_answer_to_the_same_question(monkeypatch):
    """For every step of every shape, as recorded and as every read serves it: the release
    is what the core's ``release_status`` answers for the same state, gaps and recovered
    state held back from, and what the core's own status-rule vector says for that case."""
    rule = {(c["state"], c["held_back_from"], c["gap"]): c.get("release") for c in _vectors()["status_rule"]}
    asked = set()
    for name, finding in _scenarios(monkeypatch).items():
        for row in RecoveryRecord._base_manager.filter(finding=finding).order_by("version"):
            held = row.held_back_from or None
            assert row.release == core.release_status(
                state=row.state, gap=bool(row.gaps), held_back_from=held, acceptance_carries=_carries(row.state)
            ), (name, row.version)
            assert rule[(row.state, held, bool(row.gaps))] == row.release, (name, row.version)
            asked.add((row.state, held, bool(row.gaps)))
        read = _read(finding)
        listed = next(
            i for i in rr.deployment_records(finding.deployment, offset=0, page_size=50)["incidents"]
            if i["finding"] == str(finding.uuid)
        )
        for one in (read, listed):
            for step in one["steps"]:
                key = (step["state"], step["held_back_from"], bool(step["gaps"]))
                assert step["release"] == core.release_status(
                    state=step["state"], gap=bool(step["gaps"]), held_back_from=step["held_back_from"],
                    acceptance_carries=_carries(step["state"]),
                ), (name, step["version"])
                assert rule[key] == step["release"], (name, step["version"], key)
                asked.add(key)
            assert one["current"]["release"] == one["steps"][-1]["release"]
    # The shapes reach every release word, and both recovered states held back.
    assert {rule[key] for key in asked} == {st.PASS, st.FAIL, st.AUDIT_INCOMPLETE}
    assert {held for _, held, _ in asked} >= {None, *core.RECOVERED_STATES}
    assert len(asked) >= 10, sorted(asked, key=str)


def test_the_record_computes_no_release_of_its_own():
    """The backend's rule is gone, not its callers: nothing in the module asks S1's or the
    coverage manifest's release rule, or spells a pass or a fail. The one release word it
    names is the caution a read gives when the core refuses what a row holds."""
    tree = ast.parse(inspect.getsource(rr))
    called = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not called & {"release_may_pass", "release_given_coverage"}
    words = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in ("PASS", "FAIL")]
    assert words == []
    owners = {}
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for node in ast.walk(function):
            if isinstance(node, ast.Attribute) and node.attr == "AUDIT_INCOMPLETE":
                owners.setdefault(function.name, 0)
                owners[function.name] += 1
    assert set(owners) == {"_held_of", "_served_release"}, owners


# --------------------------------------------- 2. an ended acceptance lapses on the read


def test_an_acceptance_that_ended_yesterday_reads_as_ended_today(monkeypatch):
    """The fail-first (on #234's head the read two days on is ``recovery_accepted`` and
    ``PASS``): accepted until tomorrow, read the day after, the step is not served as
    accepted. It is served at the state before it, held back from nothing, its release the
    core's (``FAIL``), and it stands ``acceptance_ended``. The row is not rewritten."""
    finding = _incident()
    recorded = timezone.now()
    steps = _accepted(finding, until=recorded + timedelta(days=1))
    before = _history(finding)
    read = _read(finding)
    assert read["current"] == {"version": 4, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}
    assert read["steps"][-1]["standing"] == core.CURRENT

    _at(monkeypatch, recorded + timedelta(days=2))
    for read in (_read(finding), rr.deployment_records(finding.deployment, offset=0, page_size=50)["incidents"][0]):
        assert read["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.FAIL}
        last = read["steps"][-1]
        assert (last["state"], last["held_back_from"], last["standing"]) == (st.REPAIR_TESTED, None, core.ACCEPTANCE_ENDED)
        assert last["recorded"] == {"state": st.RECOVERY_ACCEPTED, "gaps": [], "release": st.PASS}
        assert read["as_of"] == rr.instant(recorded + timedelta(days=2))
        # Nothing the read shows as standing is accepted or a pass.
        assert not any(s["state"] == st.RECOVERY_ACCEPTED or s["release"] == st.PASS for s in read["steps"])
    assert _history(finding) == before
    assert steps[-1].release == st.PASS, "the row is history"


def test_the_end_is_compared_with_the_readers_instant_and_not_with_the_steps_own(monkeypatch):
    finding = _incident()
    (*_, accepted) = _accepted(finding)
    end = accepted.accepted_until
    _at(monkeypatch, end - timedelta(microseconds=1))
    assert _read(finding)["current"] == {"version": 4, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}
    _at(monkeypatch, end)  # at its end, it has ended (the core's rule: at or before)
    last = _read(finding)["steps"][-1]
    assert (last["state"], last["release"], last["standing"]) == (st.REPAIR_TESTED, st.FAIL, core.ACCEPTANCE_ENDED)


def test_an_ended_acceptance_under_a_wider_scope_is_read_as_ended_first(monkeypatch):
    finding = _incident()
    primary = scopes.asset(finding.deployment, "primary-route")
    (*_, accepted) = _accepted_under(finding, primary)
    backup = scopes.asset(finding.deployment, "backup-route")
    declare_scope(finding, primary, backup)
    hold = core_scope.gap(2, core_scope.ASSET, str(backup.uuid))

    last = _read(finding)["steps"][-1]
    assert (last["state"], last["held_back_from"], last["release"], last["standing"]) == (
        st.REPAIR_TESTED, st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE, core.SCOPE_MOVED,
    )
    _at(monkeypatch, accepted.accepted_until + timedelta(days=1))
    last = _read(finding)["steps"][-1]
    # Not held back from an acceptance that has ended: it would not be accepted whatever
    # the scope. The hold is still listed.
    assert (last["state"], last["held_back_from"], last["release"], last["standing"]) == (
        st.REPAIR_TESTED, None, st.FAIL, core.ACCEPTANCE_ENDED,
    )
    assert last["gaps"] == [hold]


def test_nothing_follows_an_ended_acceptance_and_the_refusal_says_so(monkeypatch):
    finding = _incident()
    (*_, accepted) = _accepted(finding)
    _at(monkeypatch, accepted.accepted_until + timedelta(days=1))
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=finding.deployment.owner, accept_until=accepted.accepted_until + timedelta(days=30))
    assert refused.value.code == "terminal" and "ended" in str(refused.value)


# ------------------------------------------------------------ 3. a gap holds a pass back


def test_a_posted_gap_holds_the_pass_back():
    """The fail-first (on #234's head this step is ``recovery_accepted`` and ``PASS`` with
    ``edr-west-offline`` among its gaps): the gap holds the pass back, as recorded, as read,
    and through the route."""
    finding = _incident()
    steps = _accepted(finding, body={"gaps": ["edr-west-offline"]})
    last = steps[-1]
    assert (last.state, last.release, last.gaps) == (st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE, ["edr-west-offline"])
    read = _read(finding)
    assert read["current"] == {"version": 4, "state": st.RECOVERY_ACCEPTED, "release": st.AUDIT_INCOMPLETE}
    assert read["steps"][-1]["gaps_named"] == [
        {"gap": "edr-west-offline", "would_close": [
            {"kind": "recovery_step", "voucher": core.ACTOR, "voucher_words": core.voucher_words(core.ACTOR)}
        ]}
    ]
    client = APIClient()
    client.force_authenticate(user=finding.deployment.owner)
    served = client.get(f"/api/assurance/findings/{finding.uuid}/recovery-record/").json()
    assert served["current"]["release"] == st.AUDIT_INCOMPLETE


def test_a_pass_stored_beside_a_gap_is_read_as_the_core_reads_it():
    """A row recorded by the old rule with ``PASS`` beside a gap (written past the guards,
    as only the old rule wrote one): read ``AUDIT_INCOMPLETE``; what it recorded is kept."""
    finding = _incident()
    (*_, last) = _accepted(finding, body={"gaps": ["edr-west-offline"]})
    RecoveryRecord._base_manager.filter(pk=last.pk).update(release=st.PASS)
    before = _history(finding)
    step = _read(finding)["steps"][-1]
    assert (step["state"], step["release"], step["recorded"]["release"]) == (
        st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE, st.PASS,
    )
    assert _history(finding) == before


# ------------------------------------------------------------------ 4. who vouches


def test_every_witness_names_who_vouches_for_it_in_the_cores_words():
    finding = _incident()
    owner = finding.deployment.owner
    evidence = scopes.evidence_of(finding)
    permit, receipt = _signed_links(finding)
    steps = _accepted(finding, body={"evidence": [str(evidence.uuid)], "permits": [permit], "receipts": [receipt]})
    accepted = steps[-1]
    assert accepted.state == st.RECOVERY_ACCEPTED and accepted.release == st.PASS
    contract = finding.repair_contracts.get()
    closure = [c for c in accepted.conditions if c["condition"] == rr.REPAIR_TESTED][0]["witness"]["ref"]
    at = rr.instant(accepted.recorded_at)
    person = {core.ACTOR: f"user:{owner.pk}", "stated_at": at}
    achilles = {core.ENGINE: "achilles", "key_id": oc.key_id_for(oc.raw_public_key(ENGINE_KEYS["achilles"]))}
    effect = {core.ENGINE: "achilles-effect", "key_id": oc.key_id_for(oc.raw_public_key(ENGINE_KEYS["achilles-effect"]))}
    assert accepted.support == [
        {"condition": "effect_permitted", "kind": "permit", "ref": permit, **achilles},
        {"condition": "evidence_linked", "kind": "evidence", "ref": str(evidence.uuid), **person},
        {"condition": "incident_recorded", "kind": "finding", "ref": str(finding.uuid), **person},
        {"condition": "repair_agreed", "kind": "repair_contract", "ref": str(contract.uuid), **person},
        {"condition": "repair_tested", "kind": "closure_evidence", "ref": closure, **person},
    ]
    # The read of an accepted step lists the effect read back only when the state rests on it.
    step = _read(finding)["steps"][-1]
    assert step["support"] == accepted.support
    assert step["support_sentences"] == [core.support_sentence(entry) for entry in accepted.support]
    assert all(
        sentence.endswith("It is a person's statement and is not signed by an engine.")
        for entry, sentence in zip(step["support"], step["support_sentences"], strict=True) if core.ACTOR in entry
    )
    assert (step["recorded_by_ref"], step["accepted_by_ref"]) == (f"user:{owner.pk}", f"user:{owner.pk}")
    # The owner's acceptance is no support entry; it is the acceptance.
    assert not any(entry["condition"] == rr.OWNER_ACCEPTED for entry in step["support"])
    # A restored step rests on the read-back as well: signed by the effect key.
    restored = _incident("restored")
    declare_scope(restored)
    _repaired_and_tested(restored)
    permit, receipt = _signed_links(restored)
    last = rr.record(restored, by=owner, body={"permits": [permit], "receipts": [receipt], "restrictions": ["manual-only"],
                                                "coverage": COVERED})[-1]
    assert last.state == st.RESTORED_WITH_RESTRICTIONS
    assert {"condition": "effect_read_back", "kind": "receipt", "ref": receipt, **effect} in last.support


def test_a_carried_witness_keeps_the_person_and_the_time_of_the_step_that_linked_it(monkeypatch):
    finding = _incident()
    declare_scope(finding)
    admin = User.objects.create_user(username="first-admin", password="x", role=User.Roles.ADMIN)
    first_at = timezone.now() - timedelta(hours=2)
    _at(monkeypatch, first_at)
    (first,) = rr.record(finding, by=admin)
    monkeypatch.undo()
    _repaired_and_tested(finding)
    owner = finding.deployment.owner
    steps = rr.record(finding, by=owner, body={"coverage": COVERED}, accept_until=_until())
    accepted = steps[-1]
    by = {entry["kind"]: (entry[core.ACTOR], entry["stated_at"]) for entry in accepted.support}
    assert by["finding"] == (f"user:{admin.pk}", rr.instant(first.recorded_at))
    assert by["repair_contract"] == (f"user:{owner.pk}", rr.instant(accepted.recorded_at))
    assert accepted.release == st.PASS


def test_a_step_names_who_recorded_it_and_record_refuses_one_for_nobody():
    finding = _incident()
    for asked in ({}, {"body": {"permits": [_permit(finding.deployment)]}}):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, **asked)
        assert refused.value.code == "recorded_by_required"
    assert _history(finding) == []
    owner = finding.deployment.owner
    (step,) = rr.record(finding, by=owner)
    assert (step.recorded_by, step.recorded_by_ref, step.gaps) == (owner, f"user:{owner.pk}", [])


def test_a_witness_nobody_can_be_named_for_is_a_gap_with_what_would_close_it():
    """A stored step with no recorder still reads, never raises, and names each witness no
    person vouches for as a gap, with what would close it."""
    finding = _incident()
    permit = _permit(finding.deployment)
    step = _stored_with_no_recorder(finding, {"permits": [permit]})
    unvouched = f"support:incident_recorded:finding:{finding.uuid}"
    assert step.gaps == [unvouched] and step.release == st.FAIL
    # A signed record needs no person: the engine and its key vouch for it.
    assert [entry["kind"] for entry in step.support] == ["permit"]
    served = _read(finding)["steps"][-1]
    person = {"voucher": core.ACTOR, "voucher_words": core.voucher_words(core.ACTOR)}
    # And no scope is declared: said as a gap, as a receipt must say it, whatever the state.
    assert served["gaps_named"] == [
        {"gap": unvouched, "would_close": [{"kind": "finding", **person}]},
        {"gap": core_scope.NOT_DECLARED, "would_close": [{"kind": "scope_revision", **person}]},
    ]
    assert served["recorded_by_ref"] is None


def _before_sp4(finding):
    """``finding``'s steps as rows recorded before SP-4 hold them: written past the guards,
    as only a migration writes, with none of what SP-4 records."""
    RecoveryRecord._base_manager.filter(finding=finding).update(
        held_back_from=None, support=None, recorded_by_ref=None, accepted_by_ref=None
    )


def test_a_step_recorded_before_sp4_reads_every_witness_as_a_voucher_nobody_named():
    """No voucher is on record for any witness: each is a gap, the core's reading of an
    unknown voucher, and an accepted step reads ``AUDIT_INCOMPLETE`` -- less recovered than
    before, the stricter truth. The read writes nothing."""
    finding = _incident()
    owner = finding.deployment.owner
    _accepted(finding)
    _before_sp4(finding)
    before = _history(finding)
    step = _read(finding)["steps"][-1]
    assert step["support"] is None and step["support_sentences"] == []
    assert (step["state"], step["release"], step["recorded"]["release"]) == (
        st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE, st.PASS,
    )
    contract = finding.repair_contracts.get()
    assert f"support:incident_recorded:finding:{finding.uuid}" in step["gaps"]
    assert f"support:repair_agreed:repair_contract:{contract.uuid}" in step["gaps"]
    assert not any(gap.startswith("support:owner_accepted") for gap in step["gaps"])
    assert (step["recorded_by_ref"], step["accepted_by_ref"]) == (f"user:{owner.pk}", f"user:{owner.pk}")
    assert _history(finding) == before, "a read rewrites nothing"


def test_a_step_held_back_before_sp4_is_still_read_as_held_back():
    for name, body, held in (
        ("held-accept", {"coverage": GAP}, st.RECOVERY_ACCEPTED),
        ("no-scope", {"coverage": COVERED}, st.RECOVERY_ACCEPTED),
    ):
        finding = _incident(name)
        if name != "no-scope":
            declare_scope(finding)
        _repaired_and_tested(finding)
        (*_, last) = rr.record(finding, by=finding.deployment.owner, body=body, accept_until=_until())
        assert (last.state, last.held_back_from, last.release) == (st.REPAIR_TESTED, held, st.AUDIT_INCOMPLETE)
        _before_sp4(finding)
        step = _read(finding)["steps"][-1]
        assert (step["held_back_from"], step["release"]) == (held, st.AUDIT_INCOMPLETE), name
    # And from a restore, when no acceptance was in force.
    finding = _incident("held-restore")
    declare_scope(finding)
    _repaired_and_tested(finding)
    permit, receipt = _signed_links(finding)
    (*_, last) = rr.record(
        finding, by=finding.deployment.owner,
        body={"permits": [permit], "receipts": [receipt], "restrictions": ["manual-only"], "coverage": GAP},
    )
    assert last.held_back_from == st.RESTORED_WITH_RESTRICTIONS
    _before_sp4(finding)
    assert _read(finding)["steps"][-1]["held_back_from"] == st.RESTORED_WITH_RESTRICTIONS


def test_a_coverage_look_that_names_an_added_item_is_vouched_for_by_whoever_posted_it():
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary, backup = scopes.asset(dep, "primary-route"), scopes.asset(dep, "backup-route")
    declare_scope(finding, primary)
    rr.record(finding, by=owner)
    declare_scope(finding, primary, backup)
    _repaired_and_tested(finding)
    looked = {
        "sources": [*COVERED["sources"], {"source": f"asset:{backup.uuid}", "kind": "asset", "start": COVERED["sources"][0]["start"],
                                          "end": COVERED["sources"][0]["end"]}],
        "observations": [*COVERED["observations"], {"source": f"asset:{backup.uuid}", "start": COVERED["sources"][0]["start"],
                                                    "end": COVERED["sources"][0]["end"], "basis": "observed"}],
    }
    (*_, accepted) = rr.record(finding, by=owner, body={"coverage": looked}, accept_until=_until())
    assert (accepted.state, accepted.release) == (st.RECOVERY_ACCEPTED, st.PASS)
    assert {
        "condition": rr.SCOPE_ITEM_NAMED, "kind": "coverage", "ref": f"asset:{backup.uuid}", core.ACTOR: f"user:{owner.pk}",
        "stated_at": rr.instant(accepted.links["coverage_recorded_at"]),
    } in accepted.support


def test_a_typed_in_voucher_held_back_state_or_reference_is_refused_at_save():
    finding = _incident()
    owner = finding.deployment.owner
    links, coverage = rr.resolve(finding, None, None, None, by=owner)
    for field, value in (
        ("support", []),
        ("support", [{"condition": "incident_recorded", "kind": "finding", "ref": str(finding.uuid), core.ACTOR: "user:999",
                      "stated_at": "2026-01-01T00:00:00.000000Z"}]),
        ("held_back_from", st.RECOVERY_ACCEPTED),
        ("recorded_by_ref", "user:999"),
        ("accepted_by_ref", f"user:{owner.pk}"),
    ):
        row = rr.draft(finding, version=1, links=links, coverage=coverage, recorded_by=owner)
        setattr(row, field, value)
        with pytest.raises(rr.RecoveryRefused) as refused:
            row.save()
        assert refused.value.code == "not_derived", field
    assert _history(finding) == []
    rr.draft(finding, version=1, links=links, coverage=coverage, recorded_by=owner).save()
    assert len(_history(finding)) == 1


def test_a_persons_reference_outlives_their_account():
    finding = _incident()
    dep = finding.deployment
    admin = User.objects.create_user(username="leaving-admin", password="x", role=User.Roles.ADMIN)
    remover = User.objects.create_user(username="remover", password="x", role=User.Roles.ADMIN)
    revision = declare_scope(finding, by=admin)
    (step,) = rr.record(finding, by=admin)
    assert (revision.declared_by_ref, step.recorded_by_ref) == (f"user:{admin.pk}", f"user:{admin.pk}")
    client = APIClient()
    client.force_authenticate(user=remover)
    assert client.delete(f"/api/accounts/users/{admin.pk}/").status_code == 204
    served = _read(finding)["steps"][-1]
    assert (served["recorded_by"], served["recorded_by_ref"]) == (None, f"user:{admin.pk}")
    assert served["support"][0][core.ACTOR] == f"user:{admin.pk}"
    (declared,) = scope.finding_scope(finding)["revisions"]
    assert (declared["declared_by"], declared["declared_by_ref"]) == (None, f"user:{admin.pk}")
    assert dep.pk


def test_a_typed_in_declarer_reference_is_refused_and_an_earlier_revision_reads_its_key():
    finding = _incident()
    admin = User.objects.create_user(username="declarer", password="x", role=User.Roles.ADMIN)
    body = scopes.body(finding, scopes.asset(finding.deployment))
    row = IncidentScopeRevision(
        finding=finding, revision=1, supersedes=None, items=scope.resolve_items(finding, body["items"]),
        reason=body["reason"], evidence=scope.resolve_evidence(finding, body["evidence"]), declared_by=admin,
        declared_by_ref="user:999",
    )
    with pytest.raises(scope.ScopeRefused) as refused:
        row.save()
    assert refused.value.code == "malformed"
    revision = declare_scope(finding, by=admin)
    IncidentScopeRevision._base_manager.filter(pk=revision.pk).update(declared_by_ref=None)
    (served,) = scope.finding_scope(finding)["revisions"]
    assert served["declared_by_ref"] == f"user:{admin.pk}"


# -------------------------------------------------------------- 5. names, not free text


@pytest.mark.parametrize("key", ["restrictions", "gaps"])
def test_a_posted_free_text_restriction_or_gap_is_refused_with_the_cores_code(key):
    finding = _incident()
    for text in ("refunds are manual only", "edr\nwest", "-dash-first", "x" * 201, "a?b=c", "ünicode"):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, by=finding.deployment.owner, body={key: [text]})
        assert refused.value.code in (core.NOT_A_NAME, "malformed"), text
        assert text not in str(refused.value)
    assert _history(finding) == []
    client = APIClient()
    client.force_authenticate(user=finding.deployment.owner)
    answer = client.post(f"/api/assurance/findings/{finding.uuid}/recovery-record/", {key: ["two words"]}, format="json")
    assert (answer.status_code, answer.json()["code"]) == (400, core.NOT_A_NAME)
    assert "two words" not in answer.content.decode()
    assert _history(finding) == []


def test_a_posted_gap_spelled_as_one_the_record_derives_is_refused():
    finding = _incident()
    for gap in (core_scope.NOT_DECLARED, core_scope.UNREADABLE, core_scope.gap(2, core_scope.ASSET, "a"),
                "scope:anything", "support:incident_recorded:finding:x", "coverage:failed_collector:edr",
                "unnamed:gap:0", "effect_not_applied:receipt:r1"):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, by=finding.deployment.owner, body={"gaps": [gap]})
        assert refused.value.code == "not_posted", gap
    assert _history(finding) == []


def test_a_stored_free_text_is_shown_as_it_is_and_named_by_a_pointer():
    """A restriction recorded before SP-4 in words: shown as it is, named among the gaps by
    a pointer (never the words), and so it holds a pass back. The read writes nothing."""
    finding = _incident()
    (*_, accepted) = _accepted(finding, body={"restrictions": ["manual-only"]})
    assert accepted.release == st.PASS
    RecoveryRecord._base_manager.filter(pk=accepted.pk).update(restrictions=["refunds are manual only"])
    before = _history(finding)
    step = _read(finding)["steps"][-1]
    assert step["restrictions"] == ["refunds are manual only"]
    assert step["gaps"] == ["unnamed:restriction:0"]
    assert [entry["gap"] for entry in step["gaps_named"]] == ["unnamed:restriction:0"]
    assert step["release"] == st.AUDIT_INCOMPLETE
    assert "refunds are manual only" not in json.dumps(step["gaps_named"])
    assert _history(finding) == before


def test_a_free_text_carried_from_a_step_before_sp4_is_kept_and_named():
    finding = _incident()
    owner = finding.deployment.owner
    (first,) = rr.record(finding, by=owner)
    links = {**first.links, "gaps": ["edr west offline"]}
    RecoveryRecord._base_manager.filter(pk=first.pk).update(links=links)
    agree(finding)
    (proposed,) = rr.record(finding, by=owner)
    assert proposed.state == st.REPAIR_PROPOSED
    assert proposed.links["gaps"] == ["edr west offline"]
    assert proposed.gaps == ["edr west offline", "unnamed:gap:0"]
    assert [entry["gap"] for entry in _read(finding)["steps"][-1]["gaps_named"]] == [
        "unnamed:gap:0", core_scope.NOT_DECLARED,
    ]


# ------------------------------------------------------- 6. the same words as the core


def test_nothing_the_record_says_is_a_word_of_reassurance(monkeypatch):
    """Every code, standing, release, held-back state, gap name, closer, voucher word and
    sentence the record serves, and every string the module itself spells outside its
    docstrings: none is ``clean``, ``resolved``, ``secure`` or ``safe``."""
    said = []
    for finding in _scenarios(monkeypatch).values():
        for step in _read(finding)["steps"]:
            said += [step["standing"], step["release"], step["held_back_from"] or "", *step["support_sentences"]]
            for entry in step["gaps_named"]:
                said += [entry["gap"], *(closer[k] for closer in entry["would_close"] for k in closer)]
            for entry in step["support"] or ():
                said += [entry["condition"], entry["kind"], entry.get(core.ENGINE) or ""]
    tree = ast.parse(inspect.getsource(rr))
    docstrings = {
        id(node.body[0].value) for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body
        and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)
    }
    spelled = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
    ]
    assert len(spelled) > 100 and len(said) > 100
    for text in [*said, *spelled]:
        assert not _words(text) & REASSURANCE, text


def test_every_word_a_reader_sees_is_the_cores(monkeypatch):
    for finding in _scenarios(monkeypatch).values():
        read = _read(finding)
        for step in read["steps"]:
            assert step["standing"] in core.RECEIPT_STANDINGS
            assert step["release"] in st.RELEASE_STATES
            assert step["held_back_from"] in (None, *core.RECOVERED_STATES)
            for entry in step["gaps_named"]:
                assert entry["would_close"]
                for closer in entry["would_close"]:
                    assert closer["voucher_words"] == core.voucher_words(closer["voucher"])
            assert step["support_sentences"] == [core.support_sentence(e) for e in step["support"] or ()]
        assert [s["standing"] for s in read["steps"][:-1]] == [core.SUPERSEDED] * (len(read["steps"]) - 1)


def _scope_at(finding, revision):
    """The scope a receipt is taken under: revision ``revision`` of ``finding``'s, in the
    receipt's own fields (None: none declared)."""
    revisions = [r for r in scope.revisions_of([finding.pk]).get(finding.pk, []) if revision and r.revision <= revision]
    if not revisions:
        return {"scope_revision": None, "scope_ref": None, "scope_items": None, "scope_removed": None}
    standing = scope.since(revisions)
    by = {r.revision: r.declared_by_ref for r in revisions}
    return {
        "scope_revision": revisions[-1].revision,
        "scope_ref": str(revisions[-1].uuid),
        "scope_items": None if standing is None else [
            {"kind": kind, "ref": ref, "since": since} for (kind, ref), since in standing.items()
        ],
        "scope_removed": None if standing is None else [
            {**gone, "removed_by": by[gone["removed"]]} for gone in scope.removed(revisions)
        ],
    }


def _receipt(finding, row, *, as_of, state, gaps_named, support, held_back_from, scope_revision, ref):
    acceptance = None
    if row.accepted_until is not None:
        acceptance = {
            "owner": row.accepted_by_ref, "decided_at": rr.instant(row.recorded_at),
            "expires_at": rr.instant(row.accepted_until), "scope_revision": row.scope_revision,
        }
    return core.build_receipt(
        receipt_ref=ref, tenant_id="acme", deployment=str(finding.deployment.uuid), incident=str(finding.uuid),
        as_of=as_of, record=str(row.uuid), state=state, reopens=row.reopens,
        restrictions=[one for one in row.restrictions if rr.is_name(one)], held_back_from=held_back_from,
        support=support or [], acceptance=acceptance,
        gaps=[
            {"gap": entry["gap"], "would_close": [{"kind": c["kind"], "voucher": c["voucher"]} for c in entry["would_close"]]}
            for entry in gaps_named
        ],
        **_scope_at(finding, scope_revision),
    )


def test_a_receipt_of_each_step_is_one_the_core_takes_and_says_what_the_record_says(monkeypatch):
    """For the last step of every shape: the receipt the record would have issued when the
    step was recorded (its own state, gaps and scope revision, at its own instant) is
    built, signed with the vectors' test key and verified by the core; its release is the
    row's, and the standing the core gives it at the reader's instant, with the record's
    head, is the step's served standing. The receipt issued at the read, under the scope
    the step's state is read against, has the read's release."""
    keyring = core.recovery_receipt_keyring([oc.raw_public_key(_key())], other_roles={})
    later = timezone.now() + timedelta(days=60)  # every acceptance has ended by then
    standings, issued = set(), []
    for name, finding in _scenarios(monkeypatch).items():
        revisions = scope.revisions_of([finding.pk]).get(finding.pk, [])
        current = scope.current_of(revisions)
        for at in (None, later):
            if at is not None:
                _at(monkeypatch, at)
            read = _read(finding)
            monkeypatch.undo()
            step = read["steps"][-1]
            row = _row(step)
            # The step as it read when it was recorded: under the revisions on record then.
            then_revisions = [r for r in revisions if row.scope_revision and r.revision <= row.scope_revision]
            holds = rr.scope_holds_of(row.scope_revision, then_revisions, row.links, rr.manifest_of(finding, row.coverage))
            served = rr.served(row, holds, at=row.recorded_at)
            then = dict(
                as_of=rr.instant(row.recorded_at), state=row.state, gaps_named=served["gaps_named"], support=row.support,
                held_back_from=row.held_back_from or None, scope_revision=row.scope_revision, ref=f"rr-{row.version}",
            )
            if not row.support:
                # Nobody vouches for anything the step rests on (stored with no recorder,
                # which record() refuses, and linking no signed record): the core takes no
                # receipt of it, and says why. Every witness is named among its gaps.
                with pytest.raises(core.RecoveryReceiptError) as refused:
                    _receipt(finding, row, **then)
                assert refused.value.code == core.CONDITIONS_REQUIRED, name
                assert all(gap.startswith("support:") or not core_scope.is_scope_hold(gap) for gap in row.gaps)
                continue
            then = _receipt(finding, row, **then)
            assert then["release"] == row.release, name
            verdict = core.verify_receipt(core.sign_receipt(then, _key()), keyring)
            assert verdict.authentic, (name, verdict.code, verdict.reason)
            assert core.receipt_standing(
                verdict, current_scope_revision=current, latest_receipt_ref=then["receipt_ref"], at=read["as_of"]
            ) == step["standing"], (name, at)
            # Issued at the read, under the scope the step is read against: the current one.
            if row.state not in rr.RECOVERED and current != row.scope_revision:
                continue  # a step not recovered whose scope moved since: its own holds are of its revision
            under = current
            now = _receipt(
                finding, row, as_of=read["as_of"], state=step["state"], gaps_named=step["gaps_named"],
                support=step["support"], held_back_from=step["held_back_from"], scope_revision=under,
                ref=f"rr-{row.version}-now",
            )
            assert now["release"] == step["release"], (name, at)
            standings.add(step["standing"])
            issued.append((name, now["release"]))
        # An earlier step stands superseded, as a receipt of it does once a later one is the latest.
        if len(read["steps"]) > 1:
            assert read["steps"][0]["standing"] == core.SUPERSEDED
    assert standings >= {core.CURRENT, core.ACCEPTANCE_ENDED}, standings
    assert {release for _, release in issued} == {st.PASS, st.FAIL, st.AUDIT_INCOMPLETE}
    assert len(issued) >= 15, issued


# ------------------------------------------------------------- what it is, and is not


def test_the_url_conf_does_not_load_the_receipt_module():
    """The URL conf loads on whatever request a worker serves first, a stop included: it
    loads the record, not the definition of the receipt, which the record reads at first use."""
    probe = (
        "import sys, django; django.setup(); import config.urls, assurance.recovery_record;"
        "sys.exit(3 if 'mythos_core.recovery_receipt' in sys.modules else 0)"
    )
    ran = subprocess.run([sys.executable, "-c", probe], cwd=REPO, env=dict(os.environ), capture_output=True, timeout=120)
    assert ran.returncode == 0, ran.stderr.decode(errors="replace")[-600:]


def test_the_migration_adds_five_nullable_fields_and_writes_no_row():
    import importlib

    migration = importlib.import_module("assurance.migrations.0088_the_record_says_what_a_receipt_could").Migration
    assert [type(operation).__name__ for operation in migration.operations] == ["AddField"] * 5
    assert [(o.model_name, o.name) for o in migration.operations] == [
        ("recoveryrecord", "held_back_from"), ("recoveryrecord", "support"), ("recoveryrecord", "recorded_by_ref"),
        ("recoveryrecord", "accepted_by_ref"), ("incidentscoperevision", "declared_by_ref"),
    ]
    for operation in migration.operations:
        assert (operation.field.null, operation.field.has_default()) == (True, False), operation.name


def test_the_routes_keep_their_class_and_none_is_a_stop():
    for route, methods in (
        ("finding-recovery-record", {"GET": degraded.EVIDENCE_READ, "POST": degraded.EFFECT}),
        ("deployment-recovery-records", {"GET": degraded.EVIDENCE_READ}),
        ("finding-scope-revisions", {"GET": degraded.EVIDENCE_READ, "POST": degraded.EFFECT}),
    ):
        assert degraded.ROUTES[route] == methods
        assert route not in stops.STOP_ROUTES and route not in stops.EXEMPT_ROUTES
        assert set(stops.NOT_STOPS[route]) == set(methods)
    for package in ("safety", "failsafe", "pentest"):
        for path in sorted((REPO / package).rglob("*.py")):
            # Settings files are never read, by this test or anything else.
            if "migrations" in path.parts or "settings" in path.name.lower():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = {
                name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                for name in (getattr(node, "module", None) or "", *(alias.name for alias in node.names))
            }
            assert not any("recovery_receipt" in name or "recovery_record" in name for name in names), path
    assert _states  # the shared helpers are the SP-1 suite's own
