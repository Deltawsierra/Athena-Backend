"""An unsettled hold settles only on the evidence it weighed, and says what holds it (#124 review round 2).

F2-a: an audit written between an overtaken audit's row read and its token read weighed
older evidence; the token is now read first, so "settled since" means settled on this
evidence. F1-a: a re-derive that replaces a STALE reading with its own is the deriver's
move, not the audit's release. F3-a: a weighed hold (a load-bearing FAIL, an admitted
INCOMPLETE) later marked unsettled keeps its own words. M3: the token comparison in
_settled_since is load-bearing.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import transaction
from django.utils import timezone

from assurance import claims as claims_module
from assurance import evidence_audit as ea
from assurance import invalidation
from assurance.claims import apply_claim_transition, derive_claims
from assurance.models import AssuranceClaim, ClaimEvent, ClaimEvidence, ClaimVerdict
from tests.test_every_writer_decides_from_the_row_it_writes import _deployment, _person
from tests.test_no_audit_weighs_under_the_write_lock import _overtake_every_weighing
from tests.test_spine_evidence_audit import _access_claim, _current, _good

Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict


def _events(claim):
    return [
        (e.from_status, e.to_status, bool(e.by_person), e.cause)
        for e in ClaimEvent.objects.filter(claim_id=claim.pk).order_by("pk")
    ]


# ---------------------------------------------------------------------------
# F1: a release onto the deriver's NEW reading (reading under the hold was STALE)
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_f1_deriver_replacing_a_stale_reading_is_not_the_audits_release(monkeypatch):
    dep = _deployment("p-f1")
    claim = _access_claim(dep)
    assert claim.status == Status.VERIFIED
    invalidation._mark_stale(claim, timezone.now())
    assert _current(dep).status == Status.STALE
    # A person reads VERIFIED again off the stale mark (the deriver's reading too).
    apply_claim_transition(_current(dep), Status.VERIFIED, actor=_person("p-f1"), note="I read verified")
    assert claims_module._status_set_by_a_person(_current(dep))
    # A FAIL holds the person's VERIFIED at CONTRADICTED.
    fail = ea.record_claim_evidence(_current(dep), **_good(claim, outcome=V.FAIL.value))
    held = _current(dep)
    assert held.status == Status.CONTRADICTED and ea._held_by_audit(held)
    # Drift: the stale mark reaches the reading under the hold, which is nobody's now.
    invalidation._mark_stale(held, timezone.now())
    held = _current(dep)
    assert ea.reading_status(held) == Status.STALE
    assert not claims_module._status_set_by_a_person(held), "the stale mark replaced the person's reading"
    # The FAIL is invalidated, but its audit is overtaken every time: unsettled, the hold stands.
    _overtake_every_weighing(monkeypatch, held, times=ea.AUDIT_ATTEMPTS)
    ea.invalidate_claim_evidence(fail, actor=_person("p-f1-inv"), reason="probe was misaddressed")
    monkeypatch.undo()
    held = _current(dep)
    print("after invalidation:", held.status, ea.reading_status(held), bool(held.evidence_audit.get("unsettled")))
    # The re-derive lets the hold go, onto the DERIVER's VERIFIED (replacing the STALE reading).
    derive_claims(dep)
    released = _current(dep)
    print("events:", _events(released))
    print("released:", released.status, "person's?", claims_module._status_set_by_a_person(released))
    assert released.status == Status.VERIFIED
    assert not claims_module._status_set_by_a_person(released), (
        "the deriver's VERIFIED, replacing a stale mark, is read as the person's earlier VERIFIED"
    )


# ---------------------------------------------------------------------------
# F2: the stored audit was written between the last read and its token
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_f2_audit_written_before_the_token_read_is_not_of_that_evidence(monkeypatch):
    dep = _deployment("p-f2")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    assert _current(dep).status == Status.VERIFIED
    real_token = ea.evidence_token
    real_audit_of = ea.audit_of
    state = {"reads": 0, "armed": False}

    def audit_of(claim_, **kwargs):
        if "base_status" not in kwargs and state["armed"]:
            state["reads"] += 1
            if state["reads"] < ea.AUDIT_ATTEMPTS:
                AssuranceClaim.objects.filter(pk=claim_.pk).update(updated_at=timezone.now())
        return real_audit_of(claim_, **kwargs)

    def evidence_token(deployment_id, fingerprint=None):
        # On the last attempt, between its row read and its token read: a concurrent
        # audit B writes a PASS of the evidence as it was, then a FAIL is recorded (its
        # own audit not yet run -- or failed).
        if state["armed"] and state["reads"] == ea.AUDIT_ATTEMPTS - 1 and not state.get("raced"):
            state["raced"] = True
            with transaction.atomic():
                row = claims_module._locked_row(claim)
                ea._write_audit(row, real_audit_of(row, now=timezone.now() + timedelta(seconds=1)))
            ClaimEvidence.objects.create(
                deployment_id=claim.deployment_id, claim_fingerprint=claim.fingerprint, recorded_against=claim,
                **{k: v for k, v in _item_fields(claim, V.FAIL.value).items()},
            )
        return real_token(deployment_id, fingerprint)

    monkeypatch.setattr(ea, "audit_of", audit_of)
    monkeypatch.setattr(ea, "evidence_token", evidence_token)
    state["armed"] = True
    ea.audit_claim(AssuranceClaim.objects.get(pk=claim.pk))
    monkeypatch.undo()

    after = _current(dep)
    fails = ClaimEvidence.objects.filter(claim_fingerprint=claim.fingerprint, outcome=V.FAIL.value).count()
    print("raced:", state.get("raced"), "fails recorded:", fails)
    print("after:", after.status, after.evidence_verdict, "unsettled:", bool(after.evidence_audit.get("unsettled")),
          "current:", ea.served_audit(after)["audit_current"], "admitted:", after.evidence_audit.get("counts"))
    truth = ea.audit_of(after)
    print("audit taken now:", truth["verdict"], truth["status"])
    assert after.status != Status.VERIFIED or not ea.served_audit(after)["audit_current"], (
        "a FAIL nobody weighed stands behind a VERIFIED served as a current pass"
    )


def _item_fields(claim, outcome):
    kw = _good(claim, outcome=outcome)
    kw.pop("conditions", None)
    now = timezone.now()
    kw["expires_at"] = now + timedelta(days=7)
    kw["created_at"] = now
    return kw


# ---------------------------------------------------------------------------
# F3: refusal texts for holds without a contradictions list, marked unsettled
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_f3_a_load_bearing_fail_hold_marked_unsettled_still_says_the_fail_holds_it():
    dep = _deployment("p-f3")
    claim = _access_claim(dep)
    apply_claim_transition(_current(dep), Status.SUPPORTED, actor=_person("p-f3"), note="I read supported")
    ea.record_claim_evidence(_current(dep), **_good(claim, outcome=V.FAIL.value))
    held = _current(dep)
    print("held:", held.status, held.evidence_audit["verdict"], held.evidence_audit["contradictions"])
    assert ea._held_by_audit(held)
    before = ea.refusal_for_transition(held, ea.reading_status(held))
    with transaction.atomic():
        row = claims_module._locked_row(held)
        ea._record_unsettled(row, timezone.now())
    held = _current(dep)
    after = ea.refusal_for_transition(held, ea.reading_status(held))
    print("BEFORE:", before)
    print("AFTER: ", after)
    assert "invalidate an item" in after, "the FAIL still holds the claim; the refusal no longer says to resolve it"


@pytest.mark.django_db
def test_f3_an_incomplete_hold_marked_unsettled():
    dep = _deployment("p-f3i")
    claim = _access_claim(dep)
    ea.record_claim_evidence(_current(dep), **_good(claim, outcome=V.INCOMPLETE.value))
    held = _current(dep)
    print("held:", held.status, held.evidence_audit["verdict"], held.evidence_audit["contradictions"])
    if not ea._held_by_audit(held):
        pytest.skip("not held")
    with transaction.atomic():
        row = claims_module._locked_row(held)
        ea._record_unsettled(row, timezone.now())
    held = _current(dep)
    after = ea.refusal_for_transition(held, ea.reading_status(held))
    print("AFTER: ", after)
    assert "invalidate an item" in after


@pytest.mark.django_db(transaction=True)
def test_m3_the_token_check_in_settled_since_is_load_bearing(monkeypatch):
    """Passes on 2a24b89; fails if _settled_since's token comparison is removed (no
    existing test catches that mutant)."""
    dep = _deployment("p-m3")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    real_audit_of = ea.audit_of
    state = {"reads": 0}

    def audit_of(claim_, **kwargs):
        out = real_audit_of(claim_, **kwargs)
        if "base_status" not in kwargs:
            state["reads"] += 1
            if state["reads"] < ea.AUDIT_ATTEMPTS:
                AssuranceClaim.objects.filter(pk=claim_.pk).update(updated_at=timezone.now())
            elif state["reads"] == ea.AUDIT_ATTEMPTS:
                # After the last weighing: a concurrent audit of the same evidence writes, then
                # a FAIL is recorded whose own audit has not run yet.
                with transaction.atomic():
                    row = claims_module._locked_row(claim_)
                    ea._write_audit(row, real_audit_of(row, now=timezone.now() + timedelta(seconds=1)))
                ClaimEvidence.objects.create(
                    deployment_id=claim.deployment_id, claim_fingerprint=claim.fingerprint,
                    recorded_against=claim, **_item_fields(claim, V.FAIL.value),
                )
        return out

    monkeypatch.setattr(ea, "audit_of", audit_of)
    ea.audit_claim(AssuranceClaim.objects.get(pk=claim.pk))
    monkeypatch.undo()
    after = _current(dep)
    assert after.status == Status.UNKNOWN and after.evidence_audit.get("unsettled")
