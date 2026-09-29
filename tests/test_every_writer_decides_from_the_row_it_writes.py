"""SPINE #333, round 4: every writer of a claim -- not only a person's transition --
decides from the row as committed when it writes, and no stop waits on evidence
work.

Round 3 made a person's transition re-read the claim under the write lock. The
other writers still decided from whatever copy their caller held (round 4, X1):

- X1a/X1b: an evidence ingest holding a claim it read before a REVOKE committed
  recorded against it and audited that copy -- a withdrawn claim read VERIFIED
  0.88 again (a successor over its failure), or UNKNOWN under a hold (a failure).
- X1c: an invalidation handed a copy of the item read before another person's
  invalidation committed re-attributed it to the later person.
- X1d: the same ingest after a person's CONTRADICT: the claim read VERIFIED, above
  a claim with the same stop and no evidence at all.

And a re-derive audited every evidence item inside its one transaction, holding
SQLite's database-wide write lock for all of it (W1): a contradiction arriving
during a recompute waited 1,071 ms at 10,000 items, and past the busy timeout the
stop was LOST. The evidence is now weighed outside the lock, and written in a
short transaction only if nothing it read has moved; a stop that landed meanwhile
is what the writer reads again.

Owner decision (round 4): a person's stop on a version carries to the version a
re-derive or a drift supersedes it with -- attributed, "carried from <uuid>" --
and no evidence lifts it.

The races run on the test database file with real threads (``transaction=True``);
the only patch waits inside the writer's evidence read, where the lock used to be
held -- nothing else is changed.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import timedelta
from itertools import count

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import claims as claims_module
from assurance import evidence_audit as ea
from assurance import invalidation
from assurance.claims import ClaimChanged, IllegalClaimTransition, apply_claim_transition, derive_claims, record_retroactive_claim
from assurance.models import Asset, AssuranceClaim, ClaimEvent, ClaimEvidence, ClaimVerdict, Deployment, EvidenceClass
from tests.test_spine_evidence_audit import _access_claim, _current, _good

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
V = ClaimVerdict

_names = count()


def _person(prefix="person"):
    # Unique across runs: the threaded tests commit their rows.
    return User.objects.create_user(
        username=f"{prefix}-r4-{next(_names)}-{uuid.uuid4().hex[:8]}", password=None, role=User.Roles.ADMIN
    )


def _deployment(name):
    return Deployment.objects.create(name=f"{name}-{uuid.uuid4().hex[:8]}", owner=_person(f"owner-{name}"))


def _client(user=None):
    client = APIClient()
    client.force_authenticate(user=user or _person("admin"))
    return client


def _stop(claim, to_status, note="stop"):
    response = _client().post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": to_status, "note": note}, format="json"
    )
    assert response.status_code == 200, response.content
    return response


def _drift(dep, name="late"):
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name=name, identifier=name,
        classification=Asset.Classification.APPROVED, metadata={"tools": []},
    )


def _conf(value):
    return -1.0 if value is None else value


# ---------------------------------------------------------------------------
# 1. The evidence writers decide from the committed row (X1a-X1d)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_successor_recorded_from_a_copy_read_before_a_revoke_is_refused_and_the_claim_stays_withdrawn():
    """X1a. The copy read UNKNOWN under a failure's hold; a revoke committed; a pass
    successor recorded from the copy released the hold -- the claim read VERIFIED
    0.88, un-revoked, with no one lifting the withdrawal."""
    claim = _access_claim(_deployment("x1a"))
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    held_copy = AssuranceClaim.objects.get(pk=claim.pk)
    assert ea._held_by_audit(held_copy)
    _stop(claim, Status.REVOKED)

    with pytest.raises(ea.EvidenceRefused, match="unwithdrawn"):
        ea.record_claim_evidence(
            held_copy, supersedes=fail,
            **_good(held_copy, outcome=V.PASS.value, observed_at=timezone.now() - timedelta(seconds=30)),
        )

    row = AssuranceClaim.objects.get(pk=claim.pk)
    assert row.status == Status.REVOKED
    assert row.confidence is None
    assert not row.events.filter(from_status=Status.REVOKED).exclude(to_status=Status.REVOKED).exists()
    assert ClaimEvidence.objects.filter(recorded_against=claim).count() == 1


@pytest.mark.django_db
def test_a_failure_recorded_from_a_copy_read_before_a_revoke_is_refused_and_the_withdrawal_stands():
    """X1b. The failure recorded from a copy read before the revoke held the
    withdrawn claim at UNKNOWN: the withdrawal undone."""
    claim = _access_claim(_deployment("x1b"))
    copy = AssuranceClaim.objects.get(pk=claim.pk)
    _stop(claim, Status.REVOKED)

    with pytest.raises(ea.EvidenceRefused):
        ea.record_claim_evidence(copy, **_good(copy, outcome=V.FAIL.value))

    assert AssuranceClaim.objects.get(pk=claim.pk).status == Status.REVOKED
    assert not ClaimEvidence.objects.filter(recorded_against=claim).exists()


@pytest.mark.django_db
def test_an_invalidation_from_a_copy_read_before_another_is_refused_and_the_first_attribution_stands():
    """X1c. Bob's copy of the item was read before Alice's invalidation committed;
    Bob's invalidation from it re-attributed the item to Bob, Alice's reason gone."""
    claim = _access_claim(_deployment("x1c"))
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    stale_item = ClaimEvidence.objects.get(pk=fail.pk)
    alice, bob = _person("alice"), _person("bob")
    ea.invalidate_claim_evidence(ClaimEvidence.objects.get(pk=fail.pk), actor=alice, reason="alice: sensor miswired")

    with pytest.raises(ea.EvidenceRefused, match="already invalidated"):
        ea.invalidate_claim_evidence(stale_item, actor=bob, reason="bob, read before alice acted")

    item = ClaimEvidence.objects.get(pk=fail.pk)
    assert item.invalidated_by_id == alice.pk
    assert item.invalidated_by_username == alice.username
    assert item.invalidation_reason == "alice: sensor miswired"


@pytest.mark.django_db
def test_evidence_recorded_from_a_copy_read_before_a_contradiction_never_lifts_the_stop_above_its_control():
    """X1d. Both claims contradicted by a person; the hostile one then took a pass
    successor from a copy read before its stop, and read VERIFIED 0.88 -- above the
    control, which has the same stop and no evidence."""
    claim = _access_claim(_deployment("x1d"))
    control = _access_claim(_deployment("x1d-control"))
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    held_copy = AssuranceClaim.objects.get(pk=claim.pk)
    _stop(claim, Status.CONTRADICTED)
    _stop(control, Status.CONTRADICTED)

    ea.record_claim_evidence(
        held_copy, supersedes=fail,
        **_good(held_copy, outcome=V.PASS.value, observed_at=timezone.now() - timedelta(seconds=30)),
    )

    row, control = AssuranceClaim.objects.get(pk=claim.pk), AssuranceClaim.objects.get(pk=control.pk)
    assert row.status == Status.CONTRADICTED
    assert ea.rank(row.status) <= ea.rank(control.status)
    assert _conf(row.confidence) <= _conf(control.confidence)
    # The caller's copy is brought to the row written.
    assert held_copy.status == Status.CONTRADICTED


@pytest.mark.django_db
def test_an_audit_of_a_copy_read_before_a_revoke_writes_nothing_over_it():
    claim = _access_claim(_deployment("audit-copy"))
    ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    copy = AssuranceClaim.objects.get(pk=claim.pk)
    _stop(claim, Status.REVOKED)

    assert ea.audit_claim(copy) is None

    row = AssuranceClaim.objects.get(pk=claim.pk)
    assert row.status == Status.REVOKED
    assert copy.status == Status.REVOKED


@pytest.mark.django_db
def test_a_stale_mark_from_a_copy_read_before_a_contradiction_never_softens_the_stop():
    """The invalidation engine's mark (drift, a fired condition): handed a copy read
    VERIFIED before a person's contradiction committed, it marked the claim STALE --
    above CONTRADICTED, the stop softened."""
    claim = _access_claim(_deployment("stale-copy"))
    copy = AssuranceClaim.objects.get(pk=claim.pk)
    _stop(claim, Status.CONTRADICTED)

    invalidation._mark_stale(copy, timezone.now())

    row = AssuranceClaim.objects.get(pk=claim.pk)
    assert row.status == Status.CONTRADICTED
    assert copy.status == Status.CONTRADICTED
    assert not row.events.filter(to_status=Status.STALE).exists()


# ---------------------------------------------------------------------------
# 2. No stop waits on evidence work (W1): weighed outside the write lock
# ---------------------------------------------------------------------------


def _seed(claim, n):
    first = ea.record_claim_evidence(claim, **_good(claim))
    rows = []
    for _ in range(n - 1):
        item = ClaimEvidence.objects.get(pk=first.pk)
        item.pk = None
        item.uuid = uuid.uuid4()
        rows.append(item)
    ClaimEvidence.objects.bulk_create(rows, batch_size=500)


class _Paused:
    """``target``'s ``name``, paused on its first call in the thread named WRITER
    until released -- the evidence read that used to run under the write lock.
    The real function runs unchanged."""

    def __init__(self, monkeypatch, target, name):
        self.reading = threading.Event()
        self.go = threading.Event()
        self.calls = 0
        original = getattr(target, name)
        paused = self

        def wrapper(*args, **kwargs):
            if threading.current_thread().name == "WRITER":
                paused.calls += 1
                if paused.calls == 1:
                    paused.reading.set()
                    paused.go.wait(10)
            return original(*args, **kwargs)

        monkeypatch.setattr(target, name, wrapper)


def _in_thread(fn, box):
    def run():
        try:
            box["result"] = fn()
        except Exception as exc:  # noqa: BLE001 -- the writer's failure is reported by the test
            box["exc"] = repr(exc)
        finally:
            connection.close()

    thread = threading.Thread(target=run, name="WRITER")
    thread.start()
    return thread


def _timed_stop(claim, to_status):
    started = time.perf_counter()
    response = _client().post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": to_status, "note": "stop"}, format="json"
    )
    return response, time.perf_counter() - started


@pytest.mark.django_db(transaction=True)
def test_a_contradiction_during_a_recompute_lands_at_once_and_the_recompute_never_writes_over_it(monkeypatch):
    """W1. The recompute read every evidence item of the deployment inside its
    transaction; the contradiction waited all of it out (1,071 ms at 10,000
    items), and past the busy timeout it was lost. Here the recompute is held in
    that read: the contradiction must not wait on it at all."""
    dep = _deployment("w1")
    claim = _access_claim(dep)
    _seed(claim, 50)
    paused = _Paused(monkeypatch, claims_module, "_evidence_by_identity")
    box: dict = {}
    thread = _in_thread(
        lambda: _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/", {}, format="json"), box
    )
    assert paused.reading.wait(20), "the recompute never read the evidence"

    response, took = _timed_stop(claim, Status.CONTRADICTED)
    paused.go.set()
    thread.join(60)

    assert response.status_code == 200, response.content
    assert took < 3.0, f"the stop waited {took:.2f}s on the recompute's evidence read"
    assert "exc" not in box, box
    assert box["result"].status_code == 200, box["result"].content
    current = _current(dep)
    assert current.pk == claim.pk
    assert current.status == Status.CONTRADICTED
    stop = current.events.exclude(actor=None).order_by("-pk").first()
    assert stop.to_status == Status.CONTRADICTED
    # The recompute found its plan overtaken, and planned again from the stop.
    assert paused.calls == 2


@pytest.mark.django_db(transaction=True)
def test_a_contradiction_during_an_evidence_ingest_lands_at_once_and_the_ingest_never_lifts_it(monkeypatch):
    """The same for an ingest: its audit read every item recorded against the claim
    inside its transaction."""
    dep = _deployment("w1-ingest")
    claim = _access_claim(dep)
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    _seed(claim, 50)
    paused = _Paused(monkeypatch, ea, "evidence_for")
    box: dict = {}
    thread = _in_thread(
        lambda: ea.record_claim_evidence(
            claim, supersedes=fail,
            **_good(claim, outcome=V.PASS.value, observed_at=timezone.now() - timedelta(seconds=30)),
        ),
        box,
    )
    assert paused.reading.wait(20), "the ingest never read the evidence"

    response, took = _timed_stop(claim, Status.CONTRADICTED)
    paused.go.set()
    thread.join(60)

    assert response.status_code == 200, response.content
    assert took < 3.0, f"the stop waited {took:.2f}s on the ingest's evidence read"
    assert "exc" not in box, box
    row = AssuranceClaim.objects.get(pk=claim.pk)
    assert row.status == Status.CONTRADICTED
    assert paused.calls >= 2


@pytest.mark.django_db(transaction=True)
def test_no_writer_reads_the_evidence_items_while_it_holds_the_write_lock():
    """The shape of W1, pinned: a re-derive, an ingest and an invalidation read the
    items recorded against a claim with no transaction open. Under the lock they
    read one aggregate of the index (the evidence token), never the items."""
    dep = _deployment("scope")
    claim = _access_claim(dep)
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    under_lock = []
    table = ClaimEvidence._meta.db_table

    def record(execute, sql, params, many, context):
        if connection.in_atomic_block and table in sql and sql.lstrip().upper().startswith("SELECT"):
            under_lock.append(sql)
        return execute(sql, params, many, context)

    with connection.execute_wrapper(record):
        derive_claims(dep)
        ea.record_claim_evidence(claim, **_good(claim, outcome=V.INCOMPLETE.value))
        ea.invalidate_claim_evidence(fail, actor=_person(), reason="probe hit staging")

    # Allowed under the lock: the token (an aggregate), and the one row an ingest's
    # successor or an invalidation locks and writes, read by its key.
    item_reads = [
        sql for sql in under_lock
        if "COUNT(" not in sql.upper() and f'WHERE "{table}"."id" = %s' not in sql
    ]
    assert under_lock, "the premise: the writers ran with the lock taken"
    assert item_reads == [], item_reads[:3]


# ---------------------------------------------------------------------------
# 3. A person's stop carries to the version that supersedes it (owner decision)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("via", ["drift", "redirected"])
def test_a_persons_contradiction_carries_to_the_version_a_drift_opens(via):
    """A person contradicted version A; an input it rests on moved and a re-derive
    opened B at the deriver's VERIFIED -- the stop lifted with no one lifting it.
    B opens contradicted, attributed to the person, carried from A."""
    dep = _deployment(f"carry-{via}")
    first = _access_claim(dep)
    person = _person("stopper")
    if via == "redirected":
        # A stop addressed to a version a re-derive had already closed lands on the
        # current one (round 3), and carries from there like any other.
        _drift(dep, "early")
        derive_claims(dep)
        apply_claim_transition(first, Status.CONTRADICTED, actor=person, note="we know it leaks")
        stopped = _current(dep)
    else:
        apply_claim_transition(first, Status.CONTRADICTED, actor=person, note="we know it leaks")
        stopped = first
    _drift(dep)

    counts = derive_claims(dep)

    assert counts["superseded"] >= 1
    current = _current(dep)
    assert current.pk != stopped.pk
    assert current.status == Status.CONTRADICTED
    assert current.confidence is None
    carried = current.events.exclude(actor=None).order_by("-pk").first()
    assert carried.actor_id == person.pk
    assert carried.to_status == Status.CONTRADICTED
    assert f"carried from {stopped.uuid}" in carried.note
    assert "we know it leaks" in carried.note
    assert claims_module._status_set_by_a_person(current)


@pytest.mark.django_db
def test_a_carried_stop_is_lifted_by_no_evidence_and_no_re_derive_only_by_a_person():
    dep = _deployment("carry-lift")
    first = _access_claim(dep)
    apply_claim_transition(first, Status.CONTRADICTED, actor=_person(), note="stop")
    _drift(dep)
    derive_claims(dep)
    current = _current(dep)
    assert current.status == Status.CONTRADICTED

    ea.record_claim_evidence(current, **_good(current, outcome=V.PASS.value))
    derive_claims(dep)
    _drift(dep, "later")
    derive_claims(dep)

    current = _current(dep)
    assert current.status == Status.CONTRADICTED, "evidence or a re-derive lifted a carried stop"
    assert sum(1 for e in ClaimEvent.objects.filter(claim__deployment=dep) if "carried from" in e.note) == 2

    apply_claim_transition(current, Status.SUPPORTED, actor=_person("reviewer"), note="fixed and re-checked")
    current.refresh_from_db()
    assert current.status == Status.SUPPORTED


@pytest.mark.django_db
def test_a_contradiction_the_evidence_holds_is_not_a_persons_stop_and_is_not_carried_as_one():
    """Only a person's stop carries attributed: a claim the EVIDENCE holds at
    CONTRADICTED is audited afresh on the new version -- the same evidence against
    the same identity holds it there -- and nobody is named for it."""
    dep = _deployment("carry-evidence")
    first = _access_claim(dep, principals=False)
    apply_claim_transition(first, Status.SUPPORTED, actor=_person(), note="reviewed")
    ea.record_claim_evidence(first, **_good(first, outcome=V.FAIL.value))
    first.refresh_from_db()
    assert first.status == Status.CONTRADICTED and ea._held_by_audit(first)
    _drift(dep)

    derive_claims(dep)

    current = _current(dep)
    assert current.pk != first.pk
    assert not any("carried from" in e.note for e in current.events.all())


# ---------------------------------------------------------------------------
# Test gaps the round-4 mutants got through (R1, R3, R4, R5, R6)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_move_read_before_the_reading_under_a_hold_moved_is_refused():
    """R1. The claim is held at CONTRADICTED and its status does not move; a person
    lowers the reading under the hold, then another lowers it again. A move decided
    from a read taken between the two is refused (409): only the reading moved."""
    dep = _deployment("r1")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    apply_claim_transition(AssuranceClaim.objects.get(pk=claim.pk), Status.PARTIALLY_VERIFIED, actor=_person())
    stale = AssuranceClaim.objects.get(pk=claim.pk)
    apply_claim_transition(AssuranceClaim.objects.get(pk=claim.pk), Status.UNKNOWN, actor=_person())
    row = AssuranceClaim.objects.get(pk=claim.pk)
    assert row.status == stale.status == Status.CONTRADICTED
    assert ea.reading_status(row) != ea.reading_status(stale)

    with pytest.raises(ClaimChanged, match="re-read"):
        apply_claim_transition(stale, Status.SUPPORTED, actor=_person(), note="read before the second move")
    assert ea.reading_status(AssuranceClaim.objects.get(pk=claim.pk)) == Status.UNKNOWN


@pytest.mark.django_db
def test_a_stop_addressed_to_a_superseded_version_never_lands_on_a_retroactive_one():
    """R3. A retroactive version of the identity is believed now (``valid_to`` null)
    but about a closed window. A stop redirected to "the version with no valid_to"
    landed there, and the claim everything reads stayed VERIFIED."""
    dep = _deployment("r3")
    old = _access_claim(dep)
    _drift(dep)
    derive_claims(dep)
    current = _current(dep)
    now = timezone.now()
    retro = record_retroactive_claim(
        dep, claim_type=ClaimType.EFFECTIVE_ACCESS, statement="last week",
        effective_from=now - timedelta(days=8), effective_to=now - timedelta(days=1),
        system_fingerprint=current.system_fingerprint, status=Status.VERIFIED,
        evidence_class=EvidenceClass.TECHNICALLY_VERIFIED.value,
    )
    assert retro.fingerprint == current.fingerprint and retro.valid_to is None

    _stop(old, Status.CONTRADICTED)

    current.refresh_from_db()
    retro.refresh_from_db()
    assert current.status == Status.CONTRADICTED
    assert retro.status == Status.VERIFIED


@pytest.mark.django_db
def test_a_stop_addressed_to_a_superseded_version_with_no_current_version_is_recorded_not_refused():
    """R6. Every version of the identity closed: nothing current to stop. The stop is
    recorded, attributed, on the version it was addressed to -- a 200, never a
    refusal."""
    dep = _deployment("r6")
    old = _access_claim(dep)
    _drift(dep)
    derive_claims(dep)
    AssuranceClaim.objects.filter(pk=_current(dep).pk).update(valid_to=timezone.now(), status=Status.SUPERSEDED)

    response = _stop(old, Status.CONTRADICTED, note="take it down")

    event = old.events.order_by("-pk").first()
    assert event.actor is not None
    assert "has no current version" in event.note
    assert response.json()["status"] == Status.SUPERSEDED


@pytest.mark.django_db
def test_an_attributed_invalidation_dated_ahead_bounds_how_long_the_audit_holds():
    """R4. An item invalidated with a date ahead still counts until then; the audit
    taken now holds only until that instant, and is not served as current past it."""
    dep = _deployment("r4")
    claim = _access_claim(dep, principals=False)
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    ahead = timezone.now() + timedelta(hours=1)
    ClaimEvidence.objects.filter(pk=fail.pk).update(
        invalidated_at=ahead, invalidation_reason="retire at the change window",
        invalidated_by=_person(), invalidated_by_username="reviewer",
    )
    claim.refresh_from_db()

    result = ea.audit_of(claim, now=timezone.now())

    assert result["held"] is True
    assert result["valid_until"] == ahead.isoformat()
    ea.audit_claim(claim)
    claim.refresh_from_db()
    assert ea.audit_is_current(claim)
    assert not ea.audit_is_current(claim, now=ahead + timedelta(seconds=1))


@pytest.mark.django_db
def test_a_persons_move_stores_the_weighing_of_its_own_audit():
    """R5. A person's move writes the audit of their reading onto the claim, and the
    whole weighing beside it must be that audit's -- not the previous one's, which
    the evidence route then served beside the new summary."""
    dep = _deployment("r5")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    claim.refresh_from_db()
    before = ea.stored_weighing(claim)

    apply_claim_transition(claim, Status.PARTIALLY_VERIFIED, actor=_person(), note="a person's reading")

    claim.refresh_from_db()
    fresh = ea.audit_of(claim, now=timezone.now())
    assert ea.stored_weighing(claim) == ea.weighing_of(fresh)
    assert ea.stored_weighing(claim) != before, "the premise: the person's reading weighs differently"


@pytest.mark.django_db
def test_illegal_moves_are_still_refused_from_the_committed_row():
    """The negative control: deciding from the row changes nothing for a move that
    was never legal."""
    claim = _access_claim(_deployment("neg"))
    with pytest.raises(IllegalClaimTransition):
        apply_claim_transition(claim, Status.STALE, actor=_person())


@pytest.mark.django_db
def test_a_re_derive_rewrites_a_weighing_the_evidence_moved_and_leaves_an_unchanged_one():
    """The re-derive skips rewriting a weighing its audit leaves as it was (its size
    grows with the evidence, and it is written under the lock). One the evidence
    moved -- an item recorded that no audit has weighed yet -- is rewritten."""
    dep = _deployment("weighing")
    claim = _access_claim(dep)
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    derive_claims(dep)
    before = ea.stored_weighing(_current(dep))
    assert len(before["admitted"]) + len(before["refused"]) == 1

    unweighed = ClaimEvidence.objects.get(pk=fail.pk)
    unweighed.pk = None
    unweighed.uuid = uuid.uuid4()
    unweighed.save()
    derive_claims(dep)

    after = ea.stored_weighing(_current(dep))
    assert len(after["admitted"]) + len(after["refused"]) == 2
    assert after == ea.weighing_of(ea.audit_of(_current(dep), now=timezone.now()))
