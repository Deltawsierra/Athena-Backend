"""A hold settles on what a later audit weighed, and on nothing it did not (#124 review round 3).

An audit overtaken on every weighing falls back: it marks the claim unsettled and
holds it, unless an audit written since weighed the evidence in force. Two ways
that read wrong:

- F1. A later ingest's own audit weighed everything, newest item included, and
  settled first. The token had moved past the one the overtaken audit read, so the
  fallback held a claim whose every item was weighed (VERIFIED, pass) at UNKNOWN,
  with nothing left pending to settle it. Each weighed audit now keeps the evidence
  it weighed (``weighed_evidence``), and that counts as settled when it is the
  evidence in force.
- F2. A stale-mark rewrote the stored audit without weighing anything, and the
  fallback read the rewrite as an audit since: no unsettled mark, and the stored
  FAIL was served as current over an invalidation nobody had weighed. A rewrite
  keeps its ``audited_at``, and only an audit weighed since counts.
- F3. The refusal over a weighed hold that a later audit could not settle said the
  claim was held at unknown. It names the hold it is.

And the stops: a revoke or a contradict over an unsettled hold lands, and nothing
later lifts it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from datetime import timedelta as _timedelta
from datetime import timezone as _tz

import pytest
from django.db import transaction
from django.utils import timezone

from assurance import claims as claims_module
from assurance import evidence_audit as ea
from assurance import invalidation
from assurance.models import AssuranceClaim, ClaimEvent, ClaimEvidence, ClaimVerdict
from tests.test_every_writer_decides_from_the_row_it_writes import _deployment, _person
from tests.test_spine_evidence_audit import _access_claim, _current, _good

Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict


def _events(claim):
    return [(e.from_status, e.to_status, e.cause) for e in ClaimEvent.objects.filter(claim_id=claim.pk).order_by("pk")]


@pytest.mark.django_db(transaction=True)
def test_a_later_audit_that_weighed_the_newest_evidence_settles_the_claim(monkeypatch):
    """A's last weighing is overtaken by a NEW PASS item whose own audit B runs to
    completion (weighs everything, writes VERIFIED/pass) before A's fallback locks.
    The token moved past A's, so _settled_since says no and A holds a claim whose
    every item is weighed at UNKNOWN -- with nothing left pending to settle it."""
    dep = _deployment("r3-p1")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    assert _current(dep).status == Status.VERIFIED
    real = ea.audit_of
    state = {"reads": 0, "inner": False}

    def audit_of(claim_, **kwargs):
        out = real(claim_, **kwargs)
        if state["inner"] or "base_status" in kwargs:
            return out
        state["reads"] += 1
        if state["reads"] < ea.AUDIT_ATTEMPTS:
            AssuranceClaim.objects.filter(pk=claim_.pk).update(updated_at=timezone.now())
        elif state["reads"] == ea.AUDIT_ATTEMPTS:
            state["inner"] = True
            try:  # a concurrent ingest: its item, then its own complete audit
                ea.record_claim_evidence(_current(dep), **_good(claim))
            finally:
                state["inner"] = False
            mid = _current(dep)
            state["mid"] = (mid.status, mid.evidence_verdict, ea.audit_is_current(mid))
        return out

    monkeypatch.setattr(ea, "audit_of", audit_of)
    ea.audit_claim(AssuranceClaim.objects.get(pk=claim.pk))
    monkeypatch.undo()
    after = _current(dep)
    assert state["mid"] == (Status.VERIFIED, V.PASS.value, True), "the later ingest's own audit settled first"
    assert after.status == Status.VERIFIED, "a claim whose evidence was all weighed (pass) is held at UNKNOWN as unsettled"
    assert not after.evidence_audit.get("unsettled")
    assert ea.audit_is_current(after)
    truth = ea.audit_of(after)
    assert (truth["verdict"], truth["status"]) == (V.PASS.value, Status.VERIFIED)


@pytest.mark.django_db(transaction=True)
def test_a_rewrite_that_weighed_nothing_settles_nothing(monkeypatch):
    """CONTRADICTED held by a FAIL; the FAIL is invalidated, its audit overtaken every
    time, and on the last attempt a stale mark rewrites the stored audit
    (hold_reading_at_stale) -- weighing nothing. _settled_since reads that rewrite as
    an audit of this evidence: no unsettled mark, and the stored FAIL is served as the
    CURRENT verdict over evidence that no longer reads fail."""
    dep = _deployment("r3-p2")
    claim = _access_claim(dep)
    claims_module.apply_claim_transition(_current(dep), Status.SUPPORTED, actor=_person("r3-p2-s"), note="supported")
    fail = ea.record_claim_evidence(_current(dep), **_good(claim, outcome=V.FAIL.value))
    held = _current(dep)
    assert held.status == Status.CONTRADICTED and ea._held_by_audit(held)
    real = ea.audit_of
    state = {"reads": 0}

    def audit_of(claim_, **kwargs):
        out = real(claim_, **kwargs)
        if "base_status" in kwargs:
            return out
        state["reads"] += 1
        if state["reads"] < ea.AUDIT_ATTEMPTS:
            AssuranceClaim.objects.filter(pk=claim_.pk).update(updated_at=timezone.now())
        elif state["reads"] == ea.AUDIT_ATTEMPTS:
            invalidation._mark_stale(_current(dep), timezone.now())
        return out

    monkeypatch.setattr(ea, "audit_of", audit_of)
    ea.invalidate_claim_evidence(fail, actor=_person("r3-p2"), reason="misaddressed")
    monkeypatch.undo()
    after = _current(dep)
    truth = ea.audit_of(after)
    served = ea.served_audit(after)
    assert not (served["audit_current"] and after.evidence_verdict != truth["verdict"]), (
        "the stored FAIL is served as current though nobody weighed the invalidation"
    )


@pytest.mark.django_db
def test_the_refusal_over_a_weighed_hold_names_that_hold():
    dep = _deployment("r3-p3")
    claim = _access_claim(dep)
    claims_module.apply_claim_transition(_current(dep), Status.SUPPORTED, actor=_person("r3-p3-s"), note="supported")
    ea.record_claim_evidence(_current(dep), **_good(claim, outcome=V.FAIL.value))
    with transaction.atomic():
        ea._record_unsettled(claims_module._locked_row(_current(dep)), timezone.now())
    held = _current(dep)
    text = ea.refusal_for_transition(held, ea.reading_status(held))
    assert held.status == Status.CONTRADICTED
    assert "held at unknown" not in text, "names a hold at unknown on a claim held at contradicted"
    assert f"holds it at {Status.CONTRADICTED.value} (as last weighed, {V.FAIL.value})" in text
    assert "could not be weighed" in text and "this hold stands until one is" in text


@pytest.mark.django_db(transaction=True)
def test_a_stop_lands_on_an_unsettled_hold_and_stays():
    """Safety: revoke / contradict over an unsettled hold are applied, and no later
    audit lifts them."""
    for stop in (Status.CONTRADICTED, Status.REVOKED):
        dep = _deployment(f"r3-p4-{stop}")
        claim = _access_claim(dep)
        ea.record_claim_evidence(claim, **_good(claim))
        with transaction.atomic():
            ea._record_unsettled(claims_module._locked_row(_current(dep)), timezone.now())
        assert _current(dep).status == Status.UNKNOWN
        claims_module.apply_claim_transition(_current(dep), stop, actor=_person(f"r3-p4-{stop}"), note="stop")
        if stop == Status.CONTRADICTED:
            ea.record_claim_evidence(_current(dep), **_good(claim))
        claims_module.derive_claims(dep)
        row = AssuranceClaim.objects.filter(deployment=dep, fingerprint=claim.fingerprint).order_by("-pk").first()
        cur = _current(dep)
        assert (cur or row).status == stop, f"a {stop} over an unsettled hold did not stand"


# ---------------------------------------------------------------------------
# Round 4: every writer of a weighed audit says what it weighed
# ---------------------------------------------------------------------------


def _overtaken_with(monkeypatch, dep, claim, meanwhile):
    """``audit_claim`` of ``claim``, overtaken on each of its weighings; on the last,
    ``meanwhile`` runs first (other writers committing in that window)."""
    real = ea.audit_of
    state = {"reads": 0, "inner": False}

    def audit_of(claim_, **kwargs):
        out = real(claim_, **kwargs)
        if state["inner"] or "base_status" in kwargs:
            return out
        state["reads"] += 1
        if state["reads"] < ea.AUDIT_ATTEMPTS:
            AssuranceClaim.objects.filter(pk=claim_.pk).update(updated_at=timezone.now())
        elif state["reads"] == ea.AUDIT_ATTEMPTS:
            state["inner"] = True
            try:
                meanwhile()
            finally:
                state["inner"] = False
        return out

    monkeypatch.setattr(ea, "audit_of", audit_of)
    ea.audit_claim(AssuranceClaim.objects.get(pk=claim.pk))
    monkeypatch.undo()


@pytest.mark.django_db(transaction=True)
def test_a_person_s_move_that_weighed_the_evidence_in_force_settles_the_claim(monkeypatch):
    """A later ingest's audit settles, then a person moves VERIFIED to SUPPORTED, and
    that move's audit weighs the evidence in force. Unstamped, the fallback held the
    weighed SUPPORTED at UNKNOWN (#124 review round 4, F1)."""
    dep = _deployment("r4-move")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    assert _current(dep).status == Status.VERIFIED
    seen = {}

    def meanwhile():
        ea.record_claim_evidence(_current(dep), **_good(claim))
        claims_module.apply_claim_transition(_current(dep), Status.SUPPORTED, actor=_person("r4-move"), note="down")
        seen["audit"] = dict(_current(dep).evidence_audit)

    _overtaken_with(monkeypatch, dep, claim, meanwhile)

    after = _current(dep)
    assert seen["audit"]["weighed_evidence"] == ea.evidence_digest(ea.evidence_token(dep.pk, claim.fingerprint))
    assert after.status == Status.SUPPORTED, f"held at {after.status} though the move weighed the evidence in force"
    assert not after.evidence_audit.get("unsettled")
    truth = ea.audit_of(after)
    assert (truth["verdict"], truth["status"]) == (V.PASS.value, Status.SUPPORTED)


@pytest.mark.django_db(transaction=True)
def test_a_re_derive_that_weighed_the_evidence_in_force_settles_the_claim(monkeypatch):
    dep = _deployment("r4-derive")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    seen = {}

    def meanwhile():
        ea.record_claim_evidence(_current(dep), **_good(claim))
        AssuranceClaim.objects.filter(pk=_current(dep).pk).update(statement="changed, so the re-derive refreshes it")
        claims_module.derive_claims(dep)
        seen["audit"] = dict(_current(dep).evidence_audit)

    _overtaken_with(monkeypatch, dep, claim, meanwhile)

    after = _current(dep)
    assert seen["audit"]["weighed_evidence"] == ea.evidence_digest(ea.evidence_token(dep.pk, claim.fingerprint))
    assert after.status == Status.VERIFIED, f"held at {after.status} though the re-derive weighed the evidence in force"
    assert not after.evidence_audit.get("unsettled")


@pytest.mark.django_db(transaction=True)
def test_a_later_audit_of_evidence_no_longer_in_force_does_not_settle_it(monkeypatch):
    """The other side: a later audit weighed the evidence as it was, and more came
    after it. That audit settles nothing, and the claim is held unsettled."""
    dep = _deployment("r4-behind")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))

    def meanwhile():
        ea.record_claim_evidence(_current(dep), **_good(claim))  # its own audit settles
        # Then an item no audit has weighed, recorded behind the audits' backs.
        ClaimEvidence.objects.create(
            **{
                **{k: v for k, v in ClaimEvidence.objects.filter(claim_fingerprint=claim.fingerprint)
                   .values().first().items() if k not in ("id", "uuid", "created_at", "superseded_by_id")},
            }
        )

    _overtaken_with(monkeypatch, dep, claim, meanwhile)

    after = _current(dep)
    assert after.evidence_audit.get("unsettled"), "an audit of evidence no longer in force settled the claim"
    assert after.status == Status.UNKNOWN


def timezone_offset(*, hours: int):
    return _tz(_timedelta(hours=hours))


def test_one_instant_digests_alike_in_any_zone():
    instant = datetime(2026, 1, 1, 12, tzinfo=UTC)
    elsewhere = instant.astimezone(timezone_offset(hours=2))
    assert instant == elsewhere
    assert ea.evidence_digest((1, 2, 0, 0, instant, 0)) == ea.evidence_digest((1, 2, 0, 0, elsewhere, 0))
    assert ea.evidence_digest((1, 2, 0, 0, instant, 0)) != ea.evidence_digest((1, 3, 0, 0, instant, 0))


@pytest.mark.django_db
def test_what_an_audit_weighed_is_bookkeeping_and_never_served():
    dep = _deployment("r4-served")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    current = _current(dep)
    assert "weighed_evidence" in current.evidence_audit
    assert "weighed_evidence" not in ea.served_audit(current)


# ---------------------------------------------------------------------------
# Round 5: the stamp is never newer than what was weighed
# ---------------------------------------------------------------------------


def _behind_the_audits(claim):
    """Record an item no audit weighs: a raw copy of the claim's first item."""
    first = ClaimEvidence.objects.filter(claim_fingerprint=claim.fingerprint).values().first()
    ClaimEvidence.objects.create(
        **{k: v for k, v in first.items() if k not in ("id", "uuid", "created_at", "superseded_by_id")}
    )


@pytest.mark.django_db(transaction=True)
def test_a_person_s_move_stamps_the_evidence_read_before_it_weighed(monkeypatch):
    """The token is read BEFORE the move's audit reads the items. Read after, an item
    recorded between the two would be in the stamp and not in the weighing: a stamp
    newer than what was weighed, which a fallback would settle on (round 5, L1)."""
    dep = _deployment("r5-move-order")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    real = ea.audit_of

    def audit_of(claim_, **kwargs):
        out = real(claim_, **kwargs)
        if kwargs.get("reading_by_person"):
            _behind_the_audits(claim)  # after the items were weighed
        return out

    monkeypatch.setattr(ea, "audit_of", audit_of)
    claims_module.apply_claim_transition(_current(dep), Status.SUPPORTED, actor=_person("r5-move"), note="down")
    monkeypatch.undo()

    stamp = _current(dep).evidence_audit["weighed_evidence"]
    assert stamp != ea.evidence_digest(ea.evidence_token(dep.pk, claim.fingerprint)), (
        "the move's stamp names an item its audit never weighed"
    )


@pytest.mark.django_db(transaction=True)
def test_a_re_derive_planned_again_stamps_the_evidence_read_before_its_items(monkeypatch):
    """A re-derive whose evidence moved under the lock plans again: the token, then the
    items. Read the other way round, an item recorded between them would be in the
    token the lock checks and not in the audit written, stamped as weighed
    (round 5, L2). The audit written weighs every item the stamp names."""
    dep = _deployment("r5-replan-order")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    AssuranceClaim.objects.filter(pk=_current(dep).pk).update(statement="changed, so the re-derive refreshes it")
    real = claims_module._evidence_by_identity
    calls = {"n": 0}

    def evidence_by_identity(deployment, fingerprint=None):
        out = real(deployment, fingerprint)
        calls["n"] += 1
        if calls["n"] <= 2:  # after the plan's read, and after the first re-plan's
            _behind_the_audits(claim)
        return out

    monkeypatch.setattr(claims_module, "_evidence_by_identity", evidence_by_identity)
    claims_module.derive_claims(dep)
    monkeypatch.undo()

    current = _current(dep)
    audit = current.evidence_audit
    weighed = sum(audit["counts"][key] for key in ("admitted", "refused"))
    in_force = ClaimEvidence.objects.filter(claim_fingerprint=claim.fingerprint).count()
    assert calls["n"] >= 3, "the re-derive did not plan again"
    if audit.get("weighed_evidence") == ea.evidence_digest(ea.evidence_token(dep.pk, claim.fingerprint)):
        assert weighed == in_force, "the stamp names evidence the written audit never weighed"
