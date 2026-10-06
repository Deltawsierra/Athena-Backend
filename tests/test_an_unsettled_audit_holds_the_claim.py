"""An unsettled audit holds the claim until an audit settles it (owner's decision on #108).

Past ``AUDIT_ATTEMPTS`` overtaken weighings the evidence is never weighed under the
write lock (round 5, C1): the stored audit is marked unsettled -- no verdict, not
current. It used to leave the claim where it stood, so a VERIFIED claim whose new
evidence read FAIL stayed VERIFIED until some later audit happened to settle it.

Now evidence nobody could weigh vouches for no pass: a claim reading above UNKNOWN is
held at UNKNOWN, its reading kept under the hold, the move recorded. A hold never
lifts a claim, one it already had stands, and the claim's next audit settles it --
released to its reading when the evidence supports it, held where the evidence puts
it when not. Only the row is written: no evidence is read under the lock.
"""

from __future__ import annotations

import pytest
from django.db import connection, transaction
from django.utils import timezone

from assurance import claims as claims_module
from assurance import evidence_audit as ea
from assurance.claims import apply_claim_transition, derive_claims
from assurance.models import AssuranceClaim, ClaimEvent, ClaimEvidence, ClaimVerdict
from tests.test_every_writer_decides_from_the_row_it_writes import _deployment, _person
from tests.test_no_audit_weighs_under_the_write_lock import _overtake_every_weighing
from tests.test_spine_evidence_audit import _access_claim, _current, _good

Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict

#: Where the audit holds a claim whose only evidence is one load-bearing FAIL.
SETTLED_ON_A_LONE_FAIL = Status.UNKNOWN


def _unsettle(claim) -> AssuranceClaim:
    """Mark ``claim``'s stored audit unsettled, as the bound does, and read it back."""
    ea._record_unsettled(AssuranceClaim.objects.get(pk=claim.pk), timezone.now())
    return AssuranceClaim.objects.get(pk=claim.pk)


@pytest.mark.django_db(transaction=True)
def test_a_verified_claim_whose_new_fail_could_not_be_weighed_is_held_not_left_verified(monkeypatch):
    dep = _deployment("u-fail")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    assert _current(dep).status == Status.VERIFIED
    _overtake_every_weighing(monkeypatch, claim, times=ea.AUDIT_ATTEMPTS)

    ea.record_claim_evidence(AssuranceClaim.objects.get(pk=claim.pk), **_good(claim, outcome=V.FAIL.value))

    held = _current(dep)
    assert held.status == Status.UNKNOWN, "a FAIL nobody could weigh does not stand behind a VERIFIED"
    assert ea._held_by_audit(held)
    assert ea.reading_status(held) == Status.VERIFIED
    assert ea.current_verdict(held) is None
    assert ea.served_audit(held)["audit_current"] is False
    event = ClaimEvent.objects.filter(claim=held).order_by("-pk").first()
    assert (event.from_status, event.to_status, event.actor) == (Status.VERIFIED, Status.UNKNOWN, None)
    assert event.cause == ClaimEvent.CAUSE_EVIDENCE_AUDIT
    assert "unsettled" in event.note


@pytest.mark.django_db
def test_the_next_audit_releases_the_hold_when_the_evidence_supports_the_reading():
    dep = _deployment("u-pass")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    held = _unsettle(_current(dep))
    assert held.status == Status.UNKNOWN and ea._held_by_audit(held)

    ea.audit_claim(held)

    held.refresh_from_db()
    assert held.status == Status.VERIFIED, "released to its reading: the evidence passes"
    assert ea.served_audit(held)["audit_current"] is True
    assert "unsettled" not in (held.evidence_audit or {})


@pytest.mark.django_db
def test_the_next_audit_holds_it_where_the_evidence_puts_it_when_not():
    dep = _deployment("u-settle-fail")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    ClaimEvidence.objects.filter(claim_fingerprint=claim.fingerprint).delete()
    held = _unsettle(_current(dep))
    ea.record_claim_evidence(held, **_good(claim, outcome=V.FAIL.value))

    settled = _current(dep)
    assert settled.status == SETTLED_ON_A_LONE_FAIL
    assert ea._held_by_audit(settled), "held where the evidence puts it, its reading kept"
    assert ea.reading_status(settled) == Status.VERIFIED
    assert ea.served_audit(settled)["audit_current"] is True
    assert "unsettled" not in settled.evidence_audit


@pytest.mark.django_db
def test_a_hold_already_in_place_stands_as_it_was():
    dep = _deployment("u-held")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    before = _current(dep)
    assert ea._held_by_audit(before)
    events = ClaimEvent.objects.filter(claim=before).count()

    after = _unsettle(before)

    assert (after.status, ea.reading_status(after)) == (before.status, ea.reading_status(before))
    assert ClaimEvent.objects.filter(claim=after).count() == events, "nothing moved, so nothing is recorded"


@pytest.mark.django_db
@pytest.mark.parametrize("low", [Status.UNKNOWN, Status.STALE, Status.CONTRADICTED])
def test_an_unsettled_audit_never_lifts_a_claim(low):
    dep = _deployment(f"u-low-{low}")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=low)

    after = _unsettle(_current(dep))

    assert after.status == low
    assert not ea._held_by_audit(after)


@pytest.mark.django_db
def test_the_hold_reads_no_evidence():
    dep = _deployment("u-no-read")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    current = _current(dep)
    table = ClaimEvidence._meta.db_table
    reads = []

    def record(execute, sql, params, many, context):
        if table in sql:
            reads.append(sql)
        return execute(sql, params, many, context)

    with connection.execute_wrapper(record):
        _unsettle(current)

    assert reads == [], reads[:2]


# ---------------------------------------------------------------------------
# Review round 1
# ---------------------------------------------------------------------------


def _locked_unsettle(claim) -> AssuranceClaim:
    """``_record_unsettled`` on the locked row, as the bound calls it."""
    with transaction.atomic():
        row = claims_module._locked_row(claim)
        ea._record_unsettled(row, timezone.now())
    return AssuranceClaim.objects.get(pk=claim.pk)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "reading, holds",
    [
        (Status.VERIFIED, True),
        (Status.PARTIALLY_VERIFIED, True),
        (Status.SUPPORTED, True),
        (Status.DRAFT, False),
        (Status.STALE, False),
        (Status.UNKNOWN, False),
        (Status.CONTRADICTED, False),
    ],
)
def test_every_reading_above_unknown_is_held_and_none_at_or_below_it(reading, holds):
    dep = _deployment(f"u-rank-{reading}")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=reading)
    events = ClaimEvent.objects.filter(claim_id=claim.pk).count()

    after = _locked_unsettle(_current(dep))

    assert ea._held_by_audit(after) is holds
    assert after.status == (Status.UNKNOWN if holds else reading)
    assert ea.reading_status(after) == reading
    assert after.evidence_verdict == ""
    assert ea.current_verdict(after) is None
    assert ClaimEvent.objects.filter(claim_id=claim.pk).count() == events + (1 if holds else 0)
    if holds:
        assert after.evidence_audit["base_confidence"] == ea.claim_confidence(reading, after.evidence_class)
        assert after.evidence_audit["verdict"] == ""
        assert after.confidence == ea.claim_confidence(Status.UNKNOWN.value, after.evidence_class)
        again = _locked_unsettle(after)
        assert ClaimEvent.objects.filter(claim_id=claim.pk).count() == events + 1, "a second unsettle moves nothing"
        assert (again.status, ea.reading_status(again)) == (Status.UNKNOWN, reading)


@pytest.mark.django_db
def test_a_re_derive_that_lets_the_hold_go_keeps_a_person_s_reading():
    """F1: the release a re-derive writes is the audit's move, not the deriver's. Written
    as the deriver's, it hid a person's SUPPORTED, and the next re-derive lifted the
    claim to the deriver's VERIFIED."""
    dep = _deployment("u-person")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    apply_claim_transition(_current(dep), Status.SUPPORTED, actor=_person("u-mover"), note="I read supported")
    held = _locked_unsettle(_current(dep))
    assert (held.status, ea.reading_status(held)) == (Status.UNKNOWN, Status.SUPPORTED)

    derive_claims(dep)
    released = _current(dep)
    assert released.status == Status.SUPPORTED
    last = ClaimEvent.objects.filter(claim=released).order_by("-pk").first()
    assert (last.from_status, last.to_status, last.cause) == (Status.UNKNOWN, Status.SUPPORTED, ClaimEvent.CAUSE_EVIDENCE_AUDIT)
    assert claims_module._status_set_by_a_person(released)

    derive_claims(dep)
    assert _current(dep).status == Status.SUPPORTED, "a person's SUPPORTED was lifted to the deriver's reading"


@pytest.mark.django_db(transaction=True)
def test_an_audit_overtaken_by_audits_of_the_same_evidence_is_settled_not_held(monkeypatch):
    """F2: every weighing is overtaken by a concurrent audit that weighed the very
    evidence it read and wrote a current PASS. The claim is settled: it stays
    VERIFIED, and its stored audit is the concurrent one, current."""
    dep = _deployment("u-concurrent")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    real = ea.audit_of
    overtaken = []

    def audit_of(claim_, **kwargs):
        out = real(claim_, **kwargs)
        if "base_status" not in kwargs and len(overtaken) < ea.AUDIT_ATTEMPTS:
            overtaken.append(1)
            with transaction.atomic():
                row = claims_module._locked_row(claim_)
                ea._write_audit(row, real(row))
        return out

    monkeypatch.setattr(ea, "audit_of", audit_of)
    ea.record_claim_evidence(AssuranceClaim.objects.get(pk=claim.pk), **_good(claim))
    monkeypatch.undo()

    settled = _current(dep)
    assert len(overtaken) == ea.AUDIT_ATTEMPTS
    assert settled.status == Status.VERIFIED
    assert "unsettled" not in settled.evidence_audit
    assert ea.served_audit(settled)["audit_current"] is True


@pytest.mark.django_db
def test_an_unsettled_hold_s_refusal_says_what_settles_it_and_prints_no_empty_verdict():
    dep = _deployment("u-refusal")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    held = _locked_unsettle(_current(dep))

    text = ea.refusal_for_transition(held, Status.VERIFIED)

    assert "()" not in text
    assert "(unsettled)" in text
    assert "next audit" in text
    assert "invalidate an item" not in text, "nothing is necessarily wrong with the evidence"


@pytest.mark.django_db
def test_a_contradiction_s_hold_marked_unsettled_still_names_the_item_that_contradicts_it():
    dep = _deployment("u-refusal-c")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    held = _current(dep)
    contradictions = held.evidence_audit.get("contradictions") or []
    assert contradictions and ea._held_by_audit(held)
    held = _locked_unsettle(held)

    text = ea.refusal_for_transition(held, ea.reading_status(held))

    assert contradictions[0].rstrip(".")[:60] in text
    assert "could not be weighed" in text
    assert "invalidate an item" in text
