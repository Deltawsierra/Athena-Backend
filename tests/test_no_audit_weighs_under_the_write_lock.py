"""Round 5 (C1): no audit weighs the evidence under the write lock, even when every
weighing it takes outside the lock is overtaken.

``audit_claim`` weighs outside the lock and writes only if neither the claim nor
its evidence moved (round 4). After ``AUDIT_ATTEMPTS`` (5) overtaken weighings it
weighed ONCE MORE UNDER the lock -- and a stop issued then waited out a weighing
that grows with the evidence: 601 ms at 5,000 items, against 41 ms alone.

Now, past the bound, the stored audit is marked unsettled under the lock -- no
verdict, served not current with the reason -- reading nothing but the row, and a
hold it had stands as it was. The claim's next audit settles it.
"""

from __future__ import annotations

import threading
import time

import pytest
from django.db import connection
from django.utils import timezone

from assurance import claims as claims_module
from assurance import evidence_audit as ea
from assurance.models import AssuranceClaim, ClaimEvidence, ClaimVerdict
from tests.test_every_writer_decides_from_the_row_it_writes import _client, _deployment, _person, _seed
from tests.test_spine_evidence_audit import _access_claim, _current, _good

Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict


def _overtake_every_weighing(monkeypatch, claim, times, *, thread=None):
    """Each of the first ``times`` weighings an audit takes (in ``thread``, if given)
    is overtaken: another writer moves the claim's row before it can be written."""
    real = ea.audit_of
    weighings = []

    def audit_of(claim_, **kwargs):
        out = real(claim_, **kwargs)
        mine = thread is None or threading.current_thread().name == thread
        if mine and "base_status" not in kwargs:
            weighings.append(1)
            if len(weighings) <= times:
                AssuranceClaim.objects.filter(pk=claim.pk).update(updated_at=timezone.now())
        return out

    monkeypatch.setattr(ea, "audit_of", audit_of)
    return weighings


@pytest.mark.django_db(transaction=True)
def test_an_audit_overtaken_at_every_weighing_is_marked_unsettled_and_never_weighed_under_the_lock(monkeypatch):
    """C1, and the killer for E6 (the fallback gives up silently): the stored PASS
    must not go on being served as the verdict over a FAIL nobody could weigh."""
    dep = _deployment("c1")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    assert ea.current_verdict(_current(dep)) == V.PASS.value
    weighings = _overtake_every_weighing(monkeypatch, claim, times=ea.AUDIT_ATTEMPTS)
    under_lock = []
    table = ClaimEvidence._meta.db_table

    def record(execute, sql, params, many, context):
        if connection.in_atomic_block and table in sql and sql.lstrip().upper().startswith("SELECT"):
            under_lock.append(sql)
        return execute(sql, params, many, context)

    with connection.execute_wrapper(record):
        ea.record_claim_evidence(AssuranceClaim.objects.get(pk=claim.pk), **_good(claim, outcome=V.FAIL.value))

    assert len(weighings) == ea.AUDIT_ATTEMPTS, "the evidence was weighed again after the bound"
    item_reads = [sql for sql in under_lock if "COUNT(" not in sql.upper() and f'WHERE "{table}"."id" = %s' not in sql]
    assert item_reads == [], item_reads[:3]
    current = _current(dep)
    assert ea.current_verdict(current) is None
    served = ea.served_audit(current)
    assert served["audit_current"] is False
    assert "could not be weighed" in served["not_current_reason"]
    # Nothing moved the claim: it was not weighed, so nothing held or released it.
    assert current.status == Status.VERIFIED

    # The claim's next audit settles it.
    monkeypatch.undo()
    ea.audit_claim(current)
    current.refresh_from_db()
    assert ea.served_audit(current)["audit_current"] is True
    assert current.evidence_verdict == V.CONTESTED.value
    assert current.status == Status.UNKNOWN


@pytest.mark.django_db
def test_an_unsettled_audit_keeps_the_hold_it_had():
    """Releasing a hold nobody weighed would lift the claim."""
    dep = _deployment("c1-hold")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    held = _current(dep)
    assert held.status == Status.UNKNOWN and ea._held_by_audit(held)

    ea._record_unsettled(held, timezone.now())

    held.refresh_from_db()
    assert held.status == Status.UNKNOWN
    assert ea._held_by_audit(held)
    assert ea.reading_status(held) == Status.VERIFIED
    assert ea.current_verdict(held) is None


@pytest.mark.django_db(transaction=True)
def test_a_contradiction_issued_when_the_audit_runs_out_of_attempts_waits_no_weighing(monkeypatch):
    """C1's timing: 5,000 items; every weighing outside the lock is overtaken, and a
    contradiction is issued the moment the audit takes the lock after the last one.
    It used to wait out the weighing under the lock."""
    alone_dep = _deployment("c1-alone")
    alone_claim = _access_claim(alone_dep)
    _seed(alone_claim, 5000)
    person = _client(_person("c1-stopper"))

    def contradict(target):
        began = time.perf_counter()
        response = person.post(
            f"/api/assurance/claims/{target.uuid}/transition/", {"to_status": "contradicted", "note": "stop"},
            format="json",
        )
        return response, time.perf_counter() - began

    contradict(_access_claim(_deployment("c1-warm")))
    response, alone = contradict(alone_claim)
    assert response.status_code == 200

    dep = _deployment("c1-race")
    claim = _access_claim(dep)
    _seed(claim, 5000)
    weighings = _overtake_every_weighing(monkeypatch, claim, times=ea.AUDIT_ATTEMPTS, thread="AUDIT")
    real_locked = claims_module._locked_row
    locks, box = [], {}
    stop_thread = []

    def stop():
        try:
            box["response"], box["took"] = contradict(claim)
        finally:
            connection.close()

    def locked_row(claim_):
        row = real_locked(claim_)
        if threading.current_thread().name == "AUDIT":
            locks.append(1)
            if len(locks) == ea.AUDIT_ATTEMPTS + 1:
                # The lock the audit takes after its last overtaken weighing.
                thread = threading.Thread(target=stop, name="STOP")
                thread.start()
                stop_thread.append(thread)
                time.sleep(0.05)
        return row

    monkeypatch.setattr(claims_module, "_locked_row", locked_row)

    def audit():
        try:
            ea.audit_claim(AssuranceClaim.objects.get(pk=claim.pk))
        finally:
            connection.close()

    auditor = threading.Thread(target=audit, name="AUDIT")
    auditor.start()
    auditor.join(120)
    assert stop_thread, "the audit never took the lock after its last weighing"
    stop_thread[0].join(60)

    assert len(weighings) == ea.AUDIT_ATTEMPTS
    assert box["response"].status_code == 200, box["response"].content
    took = box["took"]
    assert took < 2 * alone + 0.05 + 0.2, f"the stop took {took * 1000:.0f} ms (alone {alone * 1000:.0f} ms)"
    assert _current(dep).status == Status.CONTRADICTED
