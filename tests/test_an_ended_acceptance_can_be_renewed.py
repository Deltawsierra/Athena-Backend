"""An ended acceptance can be renewed, a held step reads the current scope, and the
backend reads only the core's public names.

Athena-Backend #236 lapses an acceptance once it has ended: every read serves the step at
the state before it, ``FAIL``, standing ``acceptance_ended``. But ``record()`` refused
every step after it ``terminal``, so an owner could never accept again. Mythos-Core#85
adds the rule, ``mythos_core.scope.check_acceptance_reopen`` beside ``check_scope_reopen``:
a step after an accepted recovery is allowed when, and only when, the acceptance has ended
at that step's instant -- a renewal under the current scope revision, or any state the
status rule lets follow the state before acceptance -- and while a scope hold stands the
scope rule answers. This file holds:

1. the record to that rule: every case of its answer key
   (``tests/vectors/acceptance-reopen-v1.json``, byte for byte the core's at the pin: the
   core does not install its vectors), and every shape of it ``record()`` can produce,
   recorded through ``record()``, read, and asked of the core with the same arguments;
2. a held step's scope holds, read against the current revision (SP-4 2b's first change):
   after a narrowing removes the item that held it back, it no longer reads that hold, the
   read and the record name the same holds, and a receipt of it under the current scope is
   one the core takes;
3. the core's public names (Mythos-Core#84, #85): ``evidence_record.is_name`` and
   ``observed_effect.VERIFIED_FIELDS_V4``, never ``_NAME`` or ``_VERIFIED_FIELDS_V4``;
4. the pin: both files name the core's main.

On master the two first tests fail: the renewal is refused ``terminal``, and the held step
still reads the hold of an item a narrowing removed.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import evidence_record, observed_effect
from mythos_core import outcome as oc
from mythos_core import recovery_receipt as core
from mythos_core import scope as core_scope
from mythos_core import status as st

from assurance import incident_scope as scope
from assurance import observed_effects
from assurance import recovery_record as rr
from assurance.models import RecoveryRecord
from tests import incident_scopes as scopes
from tests.incident_scopes import declare as declare_scope
from tests.signed_chains import record_reconciliation
from tests.test_a_recovery_record_is_derived_from_its_witnesses import (
    COVERED,
    WF,
    _history,
    _incident,
    _permit,
    _repaired_and_tested,
    _states,
    _until,
)
from tests.test_the_recovery_record_says_what_a_receipt_could import _key, _receipt

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
VECTORS = Path(__file__).resolve().parent / "vectors" / "acceptance-reopen-v1.json"
#: Byte for byte Mythos-Core's tests/vectors/acceptance-reopen-v1.json at the pin.
VECTOR_SHA256 = "5f94793c8369d2a6c06d5362b7fea23ea411fcf89fa969fb290b2e376a6a9955"
#: The core's main on 16 Nov 2026: the merge of #85, which carries #84.
PIN = "a27774dc8cb0dae775a5b7dd97d15f697f011415"
RECEIPT_VECTORS = Path(__file__).resolve().parent / "vectors" / "recovery-receipt-v1.json"
#: The words no recovery receipt says, and so nothing here.
REASSURANCE = {"clean", "resolved", "secure", "safe"}


def _vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _cases() -> list[dict]:
    v = _vectors()
    return [*v["acceptance_reopen"], *v["acceptance_reopen_refused"]]


def _case(why: str) -> dict:
    (case,) = [c for c in _cases() if c["why"] == why]
    return case


def _at(monkeypatch, instant):
    """Make the server's clock read ``instant``."""
    monkeypatch.setattr(timezone, "now", lambda: instant)


def _read(finding):
    return rr.finding_record(finding)


def _row(step) -> RecoveryRecord:
    return RecoveryRecord._base_manager.get(uuid=step["ref"])


def _admin():
    return User.objects.get_or_create(username="reaccept-admin", defaults={"role": User.Roles.ADMIN})[0]


def _words(text) -> set[str]:
    return set(re.split(r"[^a-z]+", str(text).lower()))


def _accepted(finding, *records, until=None):
    """``finding``'s recovery accepted by its owner under a declared scope holding ``records``."""
    declare_scope(finding, *records)
    _repaired_and_tested(finding)
    steps = rr.record(finding, by=finding.deployment.owner, body={"coverage": COVERED}, accept_until=until or _until())
    assert steps[-1].state == st.RECOVERY_ACCEPTED
    return steps


def _signed(finding, read_back="applied"):
    """A permit of the finding's deployment and a receipt that reads its effect back."""
    dep = finding.deployment
    permit = _permit(dep)
    return permit, record_reconciliation(dep, WF, permit, read_back).receipt_id


def _watch(monkeypatch) -> list:
    """Every question put to the core's ``check_acceptance_reopen`` while the test runs,
    each still answered by the core: ``(before, after, the keyword arguments)``."""
    asked, real = [], getattr(core_scope, "check_acceptance_reopen", None)

    def check_acceptance_reopen(before, after, **kw):
        asked.append((before, after, kw))
        return real(before, after, **kw)

    # Not raising when the core has no such rule: on a core before #85 the test then fails
    # on what the record does, not on the watch.
    monkeypatch.setattr(core_scope, "check_acceptance_reopen", check_acceptance_reopen, raising=False)
    return asked


def _state(record):
    return record if isinstance(record, str) else record["state"] if isinstance(record, dict) else record.state


def _shape(before, after, kw) -> tuple:
    """What a question to the core turns on: the state before acceptance, the accepted
    state, the step's state, whether the acceptance has ended at the step's instant,
    whether a scope hold stands, and whether the step is under the current revision."""
    ended = kw["expires_at"] is not None and kw["at"] is not None and kw["expires_at"] <= kw["at"]
    return (
        _state(kw["before_acceptance"]), _state(before), _state(after), ended, bool(kw["holds"]),
        kw["scope_revision"] == kw["current_revision"],
    )


def _asked_about(asked, step) -> tuple:
    """The last question the core was asked about the recorded ``step``."""
    (*_, (before, after, kw)) = [one for one in asked if one[1].ref == str(step.uuid)]
    return before, after, kw


def _agrees(asked, step, why):
    """The record asked the core about ``step`` with arguments of the shape of the vector
    case ``why``, and recorded it as that case's answer allows."""
    case = _case(why)
    before, after, kw = _asked_about(asked, step)
    shape = _shape(before, after, kw)
    assert shape == _shape(case["before"], case["after"], case), (why, shape)
    assert "code" not in case, why
    assert (after.state, after.reopens == before.ref) == (step.state, bool(step.reopens))


# ---------------------------------------------------- 1. the core's answer key, as carried


def test_the_vectors_are_the_cores_own_file_and_name_the_cores_codes():
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == VECTOR_SHA256
    v = _vectors()
    assert v["schema"] == "mythos.acceptance-reopen-vectors/v1"
    assert tuple(v["refusals"]["acceptance_reopen"]) == core_scope.ACCEPTANCE_REOPEN_REFUSALS
    assert (len(v["acceptance_reopen"]), len(v["acceptance_reopen_refused"])) == (15, 37)


def _recovery(value):
    """A vector's record as the core takes it: a stored state word is passed as it is."""
    return value if isinstance(value, str) else st.Recovery(**value)


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["why"][:60])
def test_the_record_gives_the_cores_answer_to_every_case_of_its_answer_key(case):
    """Every case, allowed and refused, under either of the core's two rules: the record's
    question (:func:`recovery_record.acceptance_reopen`) allows what the core allows and
    refuses the rest with the core's code."""
    asked = dict(
        before_acceptance=_recovery(case["before_acceptance"]), expires_at=case["expires_at"], at=case["at"],
        holds=case["holds"], scope_revision=case["scope_revision"], current_revision=case["current_revision"],
    )
    if "code" not in case:
        rr.acceptance_reopen(_recovery(case["before"]), _recovery(case["after"]), **asked)
        return
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.acceptance_reopen(_recovery(case["before"]), _recovery(case["after"]), **asked)
    assert refused.value.code == case["code"], case["why"]
    assert not _words(refused.value) & REASSURANCE


# ------------------------------------------- 2. an ended acceptance is renewed, recorded


def test_an_owner_renews_an_acceptance_once_it_has_ended(monkeypatch):
    """The fail-first (on master this renewal is refused ``terminal``): an hour after the
    acceptance ended the owner accepts again. The renewal is a new step under the current
    revision, ``recovery_accepted`` and ``PASS``; the ended step stays as it was recorded,
    and reads superseded at the state before it, ``FAIL``. The core was asked, with the
    shape of its own case, and a receipt of each step is one the core takes."""
    finding = _incident()
    owner = finding.deployment.owner
    steps = _accepted(finding)
    ended = steps[-1]
    before = _history(finding)
    asked = _watch(monkeypatch)
    _at(monkeypatch, ended.accepted_until + timedelta(hours=1))

    (renewal,) = rr.record(finding, by=owner, accept_until=ended.accepted_until + timedelta(days=30))

    assert (renewal.version, renewal.state, renewal.release, renewal.scope_revision, renewal.reopens) == (
        ended.version + 1, st.RECOVERY_ACCEPTED, st.PASS, ended.scope_revision, "",
    )
    assert renewal.uuid != ended.uuid and renewal.accepted_by == owner
    _agrees(asked, renewal, "ended, then renewed under the current scope revision")
    # The same owner renews: both name the owner, as the core's case does.
    accepted_as, renewed_as, _ = _asked_about(asked, renewal)
    assert accepted_as.owner_acceptance == renewed_as.owner_acceptance == f"user:{owner.pk}"
    _agrees(asked, renewal, "the same owner renews: the renewal names the owner as the ended acceptance did")
    # History is never rewritten: every step before the renewal is what it was.
    assert _history(finding)[: len(before)] == before

    read = _read(finding)
    assert read["current"] == {"version": renewal.version, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}
    was, now = read["steps"][-2], read["steps"][-1]
    assert (was["state"], was["release"], was["held_back_from"], was["standing"]) == (
        st.REPAIR_TESTED, st.FAIL, None, core.SUPERSEDED,
    )
    assert was["recorded"] == {"state": st.RECOVERY_ACCEPTED, "gaps": [], "release": st.PASS}
    assert (now["state"], now["release"], now["standing"]) == (st.RECOVERY_ACCEPTED, st.PASS, core.CURRENT)

    # A receipt of each, issued at the read: the core takes both, and says what the read says.
    keyring = core.recovery_receipt_keyring([oc.raw_public_key(_key())], other_roles={})
    for step, ref in ((now, "rr-renewal"), (was, "rr-ended")):
        document = _receipt(
            finding, _row(step), as_of=read["as_of"], state=step["state"], gaps_named=step["gaps_named"],
            support=step["support"], held_back_from=step["held_back_from"], scope_revision=ended.scope_revision,
            ref=ref,
        )
        assert document["release"] == step["release"], ref
        verdict = core.verify_receipt(core.sign_receipt(document, _key()), keyring)
        assert verdict.authentic, (ref, verdict.code, verdict.reason)
        assert core.receipt_standing(
            verdict, current_scope_revision=read["scope_revision"], latest_receipt_ref="rr-renewal", at=read["as_of"]
        ) == step["standing"], ref


def test_an_acceptance_has_ended_at_its_end_and_not_a_microsecond_before(monkeypatch):
    finding = _incident()
    owner = finding.deployment.owner
    (*_, accepted) = _accepted(finding)
    before = _history(finding)
    asked = _watch(monkeypatch)

    _at(monkeypatch, accepted.accepted_until - timedelta(microseconds=1))
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner, accept_until=accepted.accepted_until + timedelta(days=30))
    case = _case("not yet ended: a renewal one microsecond before the end")
    assert refused.value.code == case["code"] == "terminal"
    assert not _words(refused.value) & REASSURANCE
    assert _history(finding) == before
    # Refused before anything else was checked: the core was asked about the least step
    # that can follow, a return to the investigation that names the accepted step.
    (only,) = asked
    assert (only[0].ref, only[1].state, only[1].reopens) == (
        str(accepted.uuid), st.UNDER_INVESTIGATION, str(accepted.uuid),
    )
    assert only[2]["at"] < only[2]["expires_at"]

    _at(monkeypatch, accepted.accepted_until)
    (renewal,) = rr.record(finding, by=owner, accept_until=accepted.accepted_until + timedelta(days=30))
    assert (renewal.state, renewal.release) == (st.RECOVERY_ACCEPTED, st.PASS)
    _agrees(asked, renewal, "ended at the step's own instant: an end at the step's instant has ended")


def test_nothing_follows_an_acceptance_in_force_whoever_asks_and_whatever_is_posted(monkeypatch):
    """Before it ends, every step is refused with the core's code, ``terminal``, before
    who asks, the acceptance or the links are checked, exactly as before #85; nothing is
    recorded. A lower state is refused as a renewal is."""
    finding = _incident()
    owner = finding.deployment.owner
    (*_, accepted) = _accepted(finding)
    permit, receipt = _signed(finding)
    before = _history(finding)
    asked = _watch(monkeypatch)
    for by, posted in (
        (owner, {"accept_until": _until()}),
        (_admin(), {"accept_until": _until()}),
        (None, {}),
        (owner, {"body": {"evidence": ["not-a-uuid"]}}),
        (_admin(), {"body": {"permits": [permit], "receipts": [receipt], "restrictions": ["manual-only"]}}),
        (owner, {}),
    ):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, by=by, **posted)
        assert refused.value.code == "terminal", (by, posted)
    assert _case("not yet ended: a lower state")["code"] == "terminal"
    assert _history(finding) == before
    assert {(one[1].state, one[2]["holds"] == []) for one in asked} == {(st.UNDER_INVESTIGATION, True)}


def test_a_step_drafted_after_an_acceptance_in_force_is_refused_by_the_core(monkeypatch):
    """Whoever drafts a step after an accepted one -- ``record()`` or anything else -- the
    derivation asks the core about it, so a step after an acceptance in force is never
    derived, and one after an ended acceptance is."""
    finding = _incident()
    owner = finding.deployment.owner
    (*_, accepted) = _accepted(finding)
    revisions = scope.revisions_of([finding.pk])[finding.pk]

    def drafted(at):
        return rr.draft(
            finding, version=accepted.version + 1, links=accepted.links, coverage=accepted.coverage, accepted_by=owner,
            accepted_until=accepted.accepted_until + timedelta(days=30), recorded_by=owner, recorded_at=at,
            previous=accepted, revisions=revisions,
        )

    with pytest.raises(rr.RecoveryRefused) as refused:
        drafted(accepted.accepted_until - timedelta(seconds=1))
    assert refused.value.code == "terminal"
    row = drafted(accepted.accepted_until)
    assert (row.state, row.release, row.reopens) == (st.RECOVERY_ACCEPTED, st.PASS, "")
    row.save()  # the model's own check derives it again, and the core allows it again
    assert [r["version"] for r in _history(finding)][-1] == accepted.version + 1


@pytest.mark.parametrize(("read_back", "posted", "state", "why"), [
    ("applied", {"restrictions": ["manual-only"]}, st.RESTORED_WITH_RESTRICTIONS,
     "ended, then a lower state: restored with restrictions after the tested repair"),
    ("not_applied", {}, st.RECOVERY_INCOMPLETE,
     "ended, then incomplete: verification shows the tested repair is not enough"),
], ids=["restored", "incomplete"])
def test_after_an_ended_acceptance_a_state_after_the_one_before_it_is_recorded(
    monkeypatch, read_back, posted, state, why,
):
    """Not only a renewal: any state S1 lets follow the state before acceptance. Restored
    with restrictions on a permit and its read-back, or incomplete on a failed read-back.
    A step that rests on nothing new moves nothing, and says why."""
    finding = _incident()
    (*_, accepted) = _accepted(finding)
    permit, receipt = _signed(finding, read_back)
    before = _history(finding)
    asked = _watch(monkeypatch)
    _at(monkeypatch, accepted.accepted_until + timedelta(minutes=5))
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=_admin())
    assert refused.value.code == "nothing_moved" and "ended" in str(refused.value)
    assert not _words(refused.value) & REASSURANCE
    steps = rr.record(finding, by=_admin(), body={"permits": [permit], "receipts": [receipt], **posted})
    assert _states(steps) == [state]
    _agrees(asked, steps[0], why)
    assert _history(finding)[: len(before)] == before
    read = _read(finding)
    assert read["current"]["state"] == state and read["steps"][-2]["standing"] == core.SUPERSEDED


def test_a_renewal_after_a_restricted_restore(monkeypatch):
    """The state before acceptance is the last step before the accepted run that is not an
    acceptance: here a restricted restore."""
    finding = _incident()
    declare_scope(finding)
    _repaired_and_tested(finding)
    permit, receipt = _signed(finding)
    rr.record(finding, by=_admin(), body={"permits": [permit], "receipts": [receipt], "restrictions": ["manual-only"],
                                        "coverage": COVERED})
    (accepted,) = rr.record(finding, by=finding.deployment.owner, accept_until=_until())
    assert rr.before_acceptance_of(accepted).state == st.RESTORED_WITH_RESTRICTIONS
    asked = _watch(monkeypatch)
    _at(monkeypatch, accepted.accepted_until + timedelta(seconds=1))
    renewed_until = accepted.accepted_until + timedelta(days=9)
    (renewal,) = rr.record(finding, by=finding.deployment.owner, accept_until=renewed_until)
    _agrees(asked, renewal, "ended after a restricted restore, then renewed")


def test_a_renewal_that_has_ended_in_turn_is_renewed_again(monkeypatch):
    """And still the tested repair when a renewal that has ended in turn is renewed again."""
    finding = _incident()
    (*_, tested, first) = _accepted(finding)
    asked = _watch(monkeypatch)
    _at(monkeypatch, first.accepted_until + timedelta(days=1))
    (second,) = rr.record(finding, by=finding.deployment.owner, accept_until=first.accepted_until + timedelta(days=2))
    _at(monkeypatch, second.accepted_until + timedelta(days=1))
    (third,) = rr.record(finding, by=finding.deployment.owner, accept_until=second.accepted_until + timedelta(days=30))
    assert rr.before_acceptance_of(third).uuid == rr.before_acceptance_of(second).uuid == tested.uuid
    _agrees(asked, third, (
        "a renewal that has ended in turn is renewed again: the state before acceptance is still the tested repair"
    ))
    assert [s["standing"] for s in _read(finding)["steps"][-3:]] == [core.SUPERSEDED, core.SUPERSEDED, core.CURRENT]


def test_a_renewal_is_given_under_the_current_revision_and_never_an_old_one(monkeypatch):
    """A revision that only removed an item takes no acceptance away; once it has ended,
    the renewal is recorded under the current revision. Derived under the revision the
    ended acceptance was given under, the core refuses it (``acceptance_scope_mismatch``)."""
    finding = _incident()
    owner = finding.deployment.owner
    primary, spare = scopes.asset(finding.deployment, "primary-route"), scopes.asset(finding.deployment, "spare-route")
    (*_, accepted) = _accepted(finding, primary, spare)
    declare_scope(finding, primary, by=owner, reason="the spare route was never connected")
    assert _read(finding)["current"] == {"version": accepted.version, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}
    revisions = scope.revisions_of([finding.pk])[finding.pk]
    later = accepted.accepted_until + timedelta(hours=2)

    def renewal_under(revision):
        return rr.derive(
            ref=str(uuid.uuid4()), links=accepted.links, manifest=rr.manifest_of(finding, accepted.coverage),
            accepted=f"user:{owner.pk}", previous=accepted, scope_revision=revision, revisions=revisions,
            recorded_by=f"user:{owner.pk}", recorded_at=later, before_acceptance=rr.before_acceptance_of(accepted),
        )

    with pytest.raises(rr.RecoveryRefused) as refused:
        renewal_under(1)
    assert refused.value.code == _case("a renewal under an earlier revision than the current one")["code"]
    assert renewal_under(2)["state"] == st.RECOVERY_ACCEPTED

    asked = _watch(monkeypatch)
    _at(monkeypatch, later)
    (renewal,) = rr.record(finding, by=owner, accept_until=later + timedelta(days=30))
    assert (renewal.state, renewal.release, renewal.scope_revision) == (st.RECOVERY_ACCEPTED, st.PASS, 2)
    _agrees(asked, renewal, "renewed under the current revision, after a revision that only removed an item")


@pytest.mark.parametrize("ended", [False, True], ids=["in force", "ended"])
def test_while_a_scope_hold_stands_the_scope_rule_answers_the_same_question(monkeypatch, ended):
    """A wider scope reopens an accepted recovery whether or not its acceptance has ended:
    the record asks the core's one question with the hold that stands, and the core
    answers by its scope rule."""
    finding = _incident()
    primary = scopes.asset(finding.deployment, "primary-route")
    (*_, accepted) = _accepted(finding, primary)
    backup = scopes.asset(finding.deployment, "backup-route")
    declare_scope(finding, primary, backup, reason="a backup route found in the firewall export")
    hold = core_scope.gap(2, core_scope.ASSET, str(backup.uuid))
    proof = scopes.evidence_naming(backup)
    asked = _watch(monkeypatch)
    if ended:
        _at(monkeypatch, accepted.accepted_until + timedelta(days=1))
    again = rr.record(finding, by=_admin(), body={"evidence": [str(proof.uuid)]})
    reopening = again[0]
    assert (reopening.state, reopening.reopens, reopening.scope_revision) == (
        st.UNDER_INVESTIGATION, str(accepted.uuid), 2,
    )
    _, _, kw = _asked_about(asked, reopening)
    assert kw["holds"] == [hold]
    _agrees(asked, reopening, (
        "a scope hold stands: the scope rule reopens the accepted record, which the return names with the hold"
        if ended
        else "a scope hold stands against an acceptance still in force: the scope rule reopens it, ended or not"
    ))


# --------------------------------------- 3. a held step reads the current revision's holds


def _held(finding):
    """A step held back from acceptance by one scope hold alone: revision 2 added a backup
    route nothing the step links names. Returns the held step and the backup route."""
    dep = finding.deployment
    primary, backup = scopes.asset(dep, "primary-route"), scopes.asset(dep, "backup-route")
    declare_scope(finding, primary)
    declare_scope(finding, primary, backup, reason="a backup route found in the firewall export")
    _repaired_and_tested(finding)
    steps = rr.record(finding, by=dep.owner, body={"coverage": COVERED}, accept_until=_until())
    held = steps[-1]
    hold = core_scope.gap(2, core_scope.ASSET, str(backup.uuid))
    assert (held.state, held.held_back_from, held.release, held.gaps) == (
        st.REPAIR_TESTED, st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE, [hold],
    )
    return held, primary, backup


def _status_rule(state, held_back_from, gap):
    cases = json.loads(RECEIPT_VECTORS.read_text(encoding="utf-8"))["status_rule"]
    (case,) = [c for c in cases if (c["state"], c["held_back_from"], c["gap"]) == (state, held_back_from, gap)]
    return case["release"]


def test_a_held_step_no_longer_reads_a_hold_a_narrowing_has_ended(monkeypatch):
    """The fail-first (on master the step still reads the removed item's hold, held back from
    ``recovery_accepted``, ``AUDIT_INCOMPLETE``, and a receipt of it under the current scope
    is refused ``scope_hold_mismatch``). Once revision 3 removes the backup route, the hold
    is gone: the step is held back from nothing, its release is the core's (``FAIL``), the
    read and the record name the same holds (none), and the owner's next step is accepted.
    The row is not rewritten."""
    finding = _incident()
    owner = finding.deployment.owner
    held, primary, backup = _held(finding)
    declare_scope(finding, primary, by=owner, reason="the backup route was never connected")
    before = _history(finding)

    read = _read(finding)
    step = read["steps"][-1]
    assert (step["state"], step["held_back_from"], step["gaps"], step["scope_gaps"], step["gaps_named"]) == (
        st.REPAIR_TESTED, None, [], [], [],
    )
    assert step["release"] == st.FAIL == _status_rule(st.REPAIR_TESTED, None, False)
    assert step["release"] == core.release_status(state=step["state"], gap=False, held_back_from=None)
    assert step["recorded"] == {"state": st.REPAIR_TESTED, "gaps": held.gaps, "release": st.AUDIT_INCOMPLETE}
    assert _history(finding) == before

    # The read and the record name the same holds: the read's, and those a step derived
    # now from the same links under the current revision holds back on.
    revisions = scope.revisions_of([finding.pk])[finding.pk]
    manifest = rr.manifest_of(finding, held.coverage)
    assert rr.scope_holds_of(held.scope_revision, revisions, held.links, manifest) == []
    assert rr.scope_holds_of(scope.current_of(revisions), revisions, held.links, manifest) == []

    # A receipt of it issued at the read under the current scope: the core takes it.
    keyring = core.recovery_receipt_keyring([oc.raw_public_key(_key())], other_roles={})
    document = _receipt(
        finding, held, as_of=read["as_of"], state=step["state"], gaps_named=step["gaps_named"], support=step["support"],
        held_back_from=step["held_back_from"], scope_revision=read["scope_revision"], ref="rr-held-now",
    )
    assert document["release"] == step["release"]
    assert core.verify_receipt(core.sign_receipt(document, _key()), keyring).authentic

    (accepted,) = rr.record(finding, by=owner, accept_until=_until())
    assert (accepted.state, accepted.release, accepted.scope_revision, accepted.gaps) == (
        st.RECOVERY_ACCEPTED, st.PASS, 3, [],
    )


def test_a_held_step_reads_every_hold_the_current_scope_shows_and_none_it_does_not(monkeypatch):
    """Still held, the step lists each hold the current revision shows: a later revision's
    added item beside its own, and an item removed and added again under the revision that
    added it again, never its first. A receipt of it under the current scope is one the
    core takes."""
    keyring = core.recovery_receipt_keyring([oc.raw_public_key(_key())], other_roles={})
    finding = _incident("wider")
    held, primary, backup = _held(finding)
    gateway = scopes.asset(finding.deployment, "gateway-west")
    declare_scope(finding, primary, backup, gateway, reason="a gateway found in the same export")
    step = _read(finding)["steps"][-1]
    added = [
        core_scope.gap(2, core_scope.ASSET, str(backup.uuid)), core_scope.gap(3, core_scope.ASSET, str(gateway.uuid)),
    ]
    assert (step["state"], step["held_back_from"], step["release"]) == (
        st.REPAIR_TESTED, st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE,
    )
    assert sorted(step["gaps"]) == sorted(step["scope_gaps"]) == sorted(added)

    again = _incident("again")
    held, primary, backup = _held(again)
    declare_scope(again, primary, by=again.deployment.owner, reason="the backup route was never connected")
    declare_scope(again, primary, backup, reason="the backup route was connected after all")
    step = _read(again)["steps"][-1]
    assert step["gaps"] == step["scope_gaps"] == [core_scope.gap(4, core_scope.ASSET, str(backup.uuid))]
    assert (step["held_back_from"], step["release"]) == (st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE)
    assert step["release"] == _status_rule(st.REPAIR_TESTED, st.RECOVERY_ACCEPTED, True)

    for one in (finding, again):
        read = _read(one)
        last = read["steps"][-1]
        document = _receipt(
            one, _row(last), as_of=read["as_of"], state=last["state"], gaps_named=last["gaps_named"],
            support=last["support"], held_back_from=last["held_back_from"], scope_revision=read["scope_revision"],
            ref="rr-held-now",
        )
        assert document["release"] == last["release"] == st.AUDIT_INCOMPLETE
        verdict = core.verify_receipt(core.sign_receipt(document, _key()), keyring)
        assert verdict.authentic, (verdict.code, verdict.reason)


# ------------------------------------------------------- 4. the core's public names only


def test_the_name_check_is_the_cores_public_one(monkeypatch):
    """The record asks ``evidence_record.is_name`` for every name it takes or reads: what the
    core's check answers, the record answers."""
    assert rr.is_name("edr-west-offline") and not rr.is_name("two words")
    said = []
    monkeypatch.setattr(evidence_record, "is_name", lambda value: said.append(value) or value == "asked")
    assert rr.is_name("asked") is True and rr.is_name("edr-west-offline") is False
    assert said == ["asked", "edr-west-offline"]
    finding = _incident()
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=finding.deployment.owner, body={"restrictions": ["manual-only"]})
    assert refused.value.code == core.NOT_A_NAME and said[-1] == "manual-only"


def test_the_verified_field_set_is_the_cores_public_one_and_never_its_alias(monkeypatch):
    assert observed_effects.VERIFIED_FIELDS_V4 is observed_effect.VERIFIED_FIELDS_V4
    # The private name is the public set's alias in the core until it is removed: what it
    # holds changes nothing here.
    monkeypatch.setattr(observed_effect, "_VERIFIED_FIELDS_V4", frozenset({"an-alias-nobody-reads"}), raising=False)
    assert observed_effects.VERIFIED_FIELDS_V4 is observed_effect.VERIFIED_FIELDS_V4


#: The first-party packages, every module of which is read below (settings files never).
_PACKAGES = (
    "accounts", "ai_engine", "assurance", "audit", "config", "deployment", "detection", "failsafe", "idempotency",
    "pentest", "safety", "tools",
)


def _private_core_reads(tree: ast.AST) -> list[str]:
    """Each private name of the core a module reads: one imported from a ``mythos_core``
    module, or an attribute that starts with ``_`` read from a name bound to one -- by an
    import, as the name ``core`` this backend gives the core's module where it reads one,
    or as what a function of the module that imports one returns."""
    bound, returns_core, found = {"core"}, set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("mythos_core"):
            for alias in node.names:
                if alias.name.startswith("_"):
                    found.append(f"{node.module}.{alias.name}")
                bound.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            bound.update(alias.asname or alias.name for alias in node.names if alias.name.startswith("mythos_core"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and any(
            isinstance(inner, ast.ImportFrom) and (inner.module or "").startswith("mythos_core")
            for inner in ast.walk(node)
        ):
            returns_core.add(node.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or not node.attr.startswith("_") or node.attr.startswith("__"):
            continue
        value = node.value
        if (isinstance(value, ast.Name) and value.id in bound) or (
            isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in returns_core
        ):
            found.append(f"{ast.unparse(value)}.{node.attr}")
    return found


def test_no_module_here_reads_a_private_name_of_the_core():
    """``evidence_record._NAME`` and ``observed_effect._VERIFIED_FIELDS_V4`` were the two; the
    core now names both publicly, and nothing here reads either, or any other."""
    read, seen = {}, 0
    for package in _PACKAGES:
        for path in sorted((REPO / package).rglob("*.py")):
            if "migrations" in path.parts or any("settings" in part.lower() for part in path.parts):
                continue
            seen += 1
            found = _private_core_reads(ast.parse(path.read_text(encoding="utf-8")))
            if found:
                read[str(path.relative_to(REPO))] = found
    assert seen > 100
    assert read == {}
    # The check finds what it looks for.
    assert _private_core_reads(ast.parse("from mythos_core.evidence_record import _NAME")) == [
        "mythos_core.evidence_record._NAME"
    ]
    assert _private_core_reads(ast.parse("F = {'V4': lambda core: core._VERIFIED_FIELDS_V4}")) == [
        "core._VERIFIED_FIELDS_V4"
    ]
    assert _private_core_reads(
        ast.parse("def _c():\n    from mythos_core import x\n    return x\nY = _c()._P")
    ) == ["_c()._P"]


# ---------------------------------------------------------------------------- 5. the pin


def test_both_pin_files_name_the_cores_main_and_the_readme_quotes_it():
    pinned = {
        name: re.findall(
            r"^mythos-core @ git\+https://github\.com/Deltawsierra/Mythos-Core@([0-9a-f]+)$",
            (REPO / name).read_text(encoding="utf-8"), re.MULTILINE,
        )
        for name in ("requirements.txt", "requirements-dev.txt")
    }
    assert pinned == {"requirements.txt": [PIN], "requirements-dev.txt": [PIN]}
    assert f"mythos-core pinned {PIN[:7]}, imported {PIN[:7]}" in (REPO / "README.md").read_text(encoding="utf-8")
