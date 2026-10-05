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
from django.db import connection
from django.utils import timezone

from assurance import evidence_audit as ea
from assurance.models import AssuranceClaim, ClaimEvent, ClaimEvidence, ClaimVerdict
from tests.test_no_audit_weighs_under_the_write_lock import _overtake_every_weighing
from tests.test_every_writer_decides_from_the_row_it_writes import _deployment
from tests.test_spine_evidence_audit import _access_claim, _current, _good

Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict


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
    assert settled.status in (Status.UNKNOWN, Status.CONTRADICTED)
    assert settled.status != Status.VERIFIED
    assert ea.served_audit(settled)["audit_current"] is True


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
