"""SPINE #333, round 2: a person under an evidence hold, and what readers serve.

Evidence can hold a claim back and can never lift it -- in status rank or in
confidence -- above where it would sit with no evidence recorded at all; a hold
lifts only by an attributed act; and no stop is refused, blocked or delayed by
any of it. Round 2 found three ways the hold itself broke that, each beside the
control that had no evidence:

1. A stop was refused. A person's CONTRADICT of a claim the evidence already held
   at CONTRADICTED was a 400 ("contradicted -> contradicted is not a legal claim
   transition"): the contradiction was never recorded, and a later attributed
   release lifted the claim back to the reading the person had taken down.
2. A person's downgrade under a hold was refused, because the audit would hold the
   LOWER reading too -- and the release then landed the claim on the higher reading
   the person had tried to leave, above the control that took the downgrade.
3. Every other place a claim's status is compared with a control: a differential
   fuzz of the whole machinery (drift, re-derive, latent conditions, people,
   evidence) against a deployment that records no evidence.

And the smaller ones: an invalidation nobody is attributed with could never be
made attributed (a permanent hold); the claim detail and the evidence read served
the audit a stop had not re-run as though it were the claim's verdict; and the
evidence read's offset was unbounded (a 500 past 2**63).
"""

from __future__ import annotations

import random
from datetime import timedelta
from itertools import count

import pytest
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import evidence_audit as ea
from assurance.claims import IllegalClaimTransition, apply_claim_transition, derive_claims
from assurance.invalidation import check_invalidations
from assurance.latent import declare_condition, evaluate_conditions, restore_fired_holds
from assurance.models import (
    Asset,
    AssuranceClaim,
    ClaimEvidence,
    ClaimVerdict,
    Deployment,
    LatentCondition,
)
from tests.test_spine_evidence_audit import _access_claim, _current, _good, _record

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
Origin = ClaimEvidence.Origin
V = ClaimVerdict

_names = count()


def _person(prefix="person"):
    """An admin account. No password: hashing one per account would dominate the
    fuzz below, and nothing here logs in."""
    return User.objects.create_user(username=f"{prefix}-{next(_names)}", password=None, role=User.Roles.ADMIN)


def _deployment(name):
    return Deployment.objects.create(name=name, owner=_person(f"owner-{name}"))


def _conf(value):
    """Confidence in comparison order: none is the floor."""
    return -1.0 if value is None else value


def _no_higher_than(hostile, control):
    """The invariant, as the differential fuzz states it."""
    hostile.refresh_from_db()
    control.refresh_from_db()
    assert ea.rank(hostile.status) <= ea.rank(control.status), (hostile.status, control.status)
    assert _conf(hostile.confidence) <= _conf(control.confidence), (hostile.confidence, control.confidence)


def _pair(name, *, principals, pre=None):
    """Two identical deployments: the control records no evidence, the hostile one
    will. ``pre``: a status a person moved both to first."""
    out = []
    for world in ("control", "hostile"):
        dep = _deployment(f"{name}-{world}")
        claim = _access_claim(dep, principals=principals)
        if pre is not None:
            apply_claim_transition(claim, pre, actor=_person("reviewer"), note="reviewed")
            claim.refresh_from_db()
        out.append((dep, claim))
    return out


def _persons_moves(claim):
    """The statuses people moved the claim to, oldest first."""
    return list(claim.events.exclude(actor=None).order_by("pk").values_list("to_status", flat=True))


# ---------------------------------------------------------------------------
# 1. A contradiction is a stop, and a stop is never refused
# ---------------------------------------------------------------------------


def test_a_contradiction_over_http_is_never_refused_while_the_evidence_holds_the_claim_at_contradicted():
    """N1. The evidence already held the claim at CONTRADICTED, so the person's
    contradiction was a 400 and was never recorded. An attributed invalidation of
    the failure then released the claim to the person's earlier SUPPORTED -- above
    the control, which kept the contradiction."""
    admin = _person("admin")
    client = APIClient()
    client.force_authenticate(user=admin)
    (control_dep, control), (hostile_dep, hostile) = _pair("n1", principals=False, pre=Status.SUPPORTED)
    fail = _record(hostile, outcome=V.FAIL.value)
    assert hostile.status == Status.CONTRADICTED and hostile.evidence_audit["held"] is True

    for claim in (control, hostile):
        response = client.post(
            f"/api/assurance/claims/{claim.uuid}/transition/",
            {"to_status": "contradicted", "note": "we know it leaks: take it down"},
            format="json",
        )
        assert response.status_code == 200, response.content
        claim.refresh_from_db()
        assert claim.status == Status.CONTRADICTED
        assert _persons_moves(claim)[-1] == Status.CONTRADICTED
        # The contradiction is the reading now, not something the evidence put there.
        assert ea.reading_status(claim) == Status.CONTRADICTED

    ea.invalidate_claim_evidence(fail, actor=_person("reviewer"), reason="probe hit staging")
    derive_claims(control_dep)
    derive_claims(hostile_dep)
    control, hostile = _current(control_dep), _current(hostile_dep)
    assert control.status == Status.CONTRADICTED
    assert hostile.status == Status.CONTRADICTED
    _no_higher_than(hostile, control)


def test_an_admitted_pass_never_moves_a_person_contradicted_claim_the_evidence_already_held_there():
    """N1, F2. The person's contradiction under a CONTRADICTED hold was refused, so
    a later admitted PASS made the evidence contested and the claim read UNKNOWN --
    above the person's contradiction."""
    dep = _deployment("n1-f2")
    claim = _access_claim(dep, principals=False)
    _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED and claim.evidence_audit["held"] is True

    apply_claim_transition(claim, Status.CONTRADICTED, actor=_person(), note="take it down")
    claim.refresh_from_db()
    assert claim.status == Status.CONTRADICTED

    _record(claim, outcome=V.PASS.value)
    assert claim.status == Status.CONTRADICTED
    derive_claims(dep)
    assert _current(dep).status == Status.CONTRADICTED


@pytest.mark.parametrize(
    "status",
    [Status.DRAFT, Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED, Status.UNKNOWN,
     Status.STALE, Status.CONTRADICTED, Status.REVOKED],
)
@pytest.mark.parametrize("stop", [Status.CONTRADICTED, Status.REVOKED])
def test_a_stop_is_never_refused_whatever_the_claim_reads(status, stop):
    """Whatever the claim reads -- a contradiction already, a withdrawal already --
    a person's contradict or revoke is accepted and attributed. A stop on a claim
    already withdrawn leaves it withdrawn: nothing is stronger than a withdrawal."""
    claim = _access_claim(_deployment(f"stop-{status}-{stop}"))
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=status)
    claim.refresh_from_db()
    person = _person("stopper")

    event = apply_claim_transition(claim, stop, actor=person, note="stop")

    claim.refresh_from_db()
    assert event.actor == person
    expected = Status.REVOKED if Status.REVOKED in (status, stop) else stop
    assert claim.status == expected


def test_a_contradiction_under_a_hold_does_no_evidence_work_and_nothing_the_audit_does_can_refuse_it(monkeypatch):
    """The stop under a hold records the person's reading from the stored audit it
    already has in hand: no read of the items or the route, and a broken audit
    cannot refuse it."""
    claim = _access_claim(_deployment("n1-flat"), principals=False)
    apply_claim_transition(claim, Status.SUPPORTED, actor=_person(), note="reviewed")
    claim.refresh_from_db()
    _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED and claim.evidence_audit["held"] is True

    def broken(*args, **kwargs):
        raise RuntimeError("the evidence audit is broken")

    for name in ("audit_of", "refusal_for_transition", "evidence_for", "audit", "classify", "audit_claim"):
        monkeypatch.setattr(ea, name, broken)
    monkeypatch.setattr("assurance.served_route.serving_route_now", broken)

    with CaptureQueriesContext(connection) as queries:
        apply_claim_transition(claim, Status.CONTRADICTED, actor=_person("stopper"), note="take it down")
    for q in queries.captured_queries:
        assert ClaimEvidence._meta.db_table not in q["sql"], q["sql"][:200]
    claim.refresh_from_db()
    assert claim.status == Status.CONTRADICTED
    assert ea.reading_status(claim) == Status.CONTRADICTED


# ---------------------------------------------------------------------------
# 2. A person's downgrade under a hold is the new reading under it
# ---------------------------------------------------------------------------


def test_a_persons_downgrade_under_a_contradiction_is_accepted_and_the_release_lands_on_it():
    """N2, D1. The person's SUPPORTED -> UNKNOWN was refused while a load-bearing
    failure held the claim at CONTRADICTED; its invalidation then released the
    claim to SUPPORTED, above the control's UNKNOWN."""
    (control_dep, control), (hostile_dep, hostile) = _pair("d1", principals=False, pre=Status.SUPPORTED)
    fail = _record(hostile, outcome=V.FAIL.value)
    assert hostile.status == Status.CONTRADICTED

    for claim in (control, hostile):
        apply_claim_transition(claim, Status.UNKNOWN, actor=_person(), note="less sure now")
        claim.refresh_from_db()
    # Still held -- the downgrade is the reading under the hold, not a release.
    assert hostile.status == Status.CONTRADICTED
    assert ea.reading_status(hostile) == Status.UNKNOWN
    assert _persons_moves(hostile)[-1] == Status.UNKNOWN

    ea.invalidate_claim_evidence(fail, actor=_person("reviewer"), reason="probe hit staging")
    derive_claims(control_dep)
    derive_claims(hostile_dep)
    control, hostile = _current(control_dep), _current(hostile_dep)
    assert hostile.status == control.status == Status.UNKNOWN
    _no_higher_than(hostile, control)


def test_a_persons_downgrade_under_refused_adverse_evidence_is_accepted_and_a_later_pass_lands_on_it():
    """N2, D2. A stale (refused) failure held a VERIFIED claim at UNKNOWN; the
    person's move to SUPPORTED was refused, and a later checked PASS superseding the
    stale failure lifted the claim to VERIFIED, above the control's SUPPORTED."""
    (control_dep, control), (hostile_dep, hostile) = _pair("d2", principals=True)
    now = timezone.now()
    stale = _record(hostile, outcome=V.FAIL.value, observed_at=now - timedelta(days=90), expires_at=now - timedelta(days=1))
    assert hostile.status == Status.UNKNOWN and hostile.evidence_audit["held"] is True

    for claim in (control, hostile):
        apply_claim_transition(claim, Status.SUPPORTED, actor=_person(), note="less sure now")
        claim.refresh_from_db()
    assert hostile.status == Status.UNKNOWN
    assert ea.reading_status(hostile) == Status.SUPPORTED

    ea.record_claim_evidence(hostile, supersedes=stale, **_good(hostile))
    derive_claims(control_dep)
    derive_claims(hostile_dep)
    control, hostile = _current(control_dep), _current(hostile_dep)
    assert control.status == Status.SUPPORTED
    assert hostile.status == Status.SUPPORTED
    _no_higher_than(hostile, control)


def test_a_persons_downgrade_of_a_contested_claim_to_the_status_it_is_held_at_is_accepted():
    """N2, D3. A contest held a VERIFIED claim at UNKNOWN; the person's move to
    UNKNOWN -- the status it already showed -- was illegal (UNKNOWN -> UNKNOWN), and
    the failure's invalidation released it to VERIFIED, 0.88, above the control's
    UNKNOWN. The downgrade takes the reading's own pass away, so the failure stands
    alone: the claim is held lower still, never higher."""
    (control_dep, control), (hostile_dep, hostile) = _pair("d3", principals=True)
    fail = _record(hostile, outcome=V.FAIL.value)
    assert hostile.status == Status.UNKNOWN and hostile.evidence_verdict == V.CONTESTED

    for claim in (control, hostile):
        apply_claim_transition(claim, Status.UNKNOWN, actor=_person(), note="less sure now")
        claim.refresh_from_db()
    assert ea.rank(hostile.status) <= ea.rank(Status.UNKNOWN)
    assert ea.reading_status(hostile) == Status.UNKNOWN
    _no_higher_than(hostile, control)

    ea.invalidate_claim_evidence(fail, actor=_person("reviewer"), reason="probe hit staging")
    derive_claims(control_dep)
    derive_claims(hostile_dep)
    control, hostile = _current(control_dep), _current(hostile_dep)
    assert hostile.status == control.status == Status.UNKNOWN
    _no_higher_than(hostile, control)


def test_a_person_still_cannot_take_the_reading_the_evidence_holds_the_claim_back_from():
    """The other half of N2: a move to the reading the claim already has under the
    hold asks for nothing but the hold's release, and is refused with the reason."""
    claim = _access_claim(_deployment("n2-same"), principals=False)
    _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED and ea.reading_status(claim) == Status.UNKNOWN
    with pytest.raises(IllegalClaimTransition, match="Resolve the evidence"):
        apply_claim_transition(claim, Status.UNKNOWN, actor=_person(), note="release it")
    claim.refresh_from_db()
    assert claim.status == Status.CONTRADICTED and ea.reading_status(claim) == Status.UNKNOWN


def test_a_persons_move_off_a_stale_mark_is_the_reading_and_a_re_derive_does_not_lift_past_it():
    """Found by the fuzz at 700 seeds (seed 55). A drift marked both claims STALE --
    a retest due, no reading -- and a person moved both to PARTIALLY_VERIFIED. Read
    against the mark, that was a raise the evidence would hold, and it was refused;
    once the evidence was resolved a re-derive replaced the mark with the deriver's
    VERIFIED, above the control, which kept the person's lower reading."""
    (control_dep, control), (hostile_dep, hostile) = _pair("stale-mark", principals=True)
    against = _record(hostile, outcome=V.FAIL.value, origin=Origin.TARGET.value)
    assert hostile.status == Status.UNKNOWN and hostile.evidence_audit["held"] is True
    for dep in (control_dep, hostile_dep):
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.AGENT, name="a1", identifier="a1",
            classification=Asset.Classification.APPROVED, metadata={"tools": []},
        )
        check_invalidations(dep)
        Asset.objects.filter(deployment=dep, identifier="a1").delete()
        check_invalidations(dep)
    control, hostile = _current(control_dep), _current(hostile_dep)
    assert control.status == hostile.status == Status.STALE

    for claim in (control, hostile):
        apply_claim_transition(claim, Status.PARTIALLY_VERIFIED, actor=_person(), note="partly checked")
    _no_higher_than(hostile, control)
    assert ea.reading_status(hostile) == Status.PARTIALLY_VERIFIED

    ea.invalidate_claim_evidence(against, actor=_person("reviewer"), reason="the target's own report")
    derive_claims(control_dep)
    derive_claims(hostile_dep)
    control, hostile = _current(control_dep), _current(hostile_dep)
    assert control.status == Status.PARTIALLY_VERIFIED
    assert hostile.status == Status.PARTIALLY_VERIFIED
    _no_higher_than(hostile, control)


# ---------------------------------------------------------------------------
# 3. The differential fuzz: evidence never lifts a claim above its control
# ---------------------------------------------------------------------------

_PEOPLE = [Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED, Status.CONTRADICTED, Status.UNKNOWN] * 6 + [
    Status.REVOKED
]
_EVIDENCE_OPS = ["fail", "fail", "pass", "pass_succ", "null_succ", "fail_succ", "target_fail", "stale_fail", "inval", "inval"]
_WORLD_OPS = ["drift", "derive", "derive", "fire", "clear", "restore", "person", "person", "undrift"]
_FUZZ_SEEDS = 200
_FUZZ_LENGTH = 14


class _World:
    """One deployment of the pair: the same non-evidence moves are made on both."""

    def __init__(self, name, principals):
        self.dep = _deployment(name)
        claim = _access_claim(self.dep, principals=principals)
        self.drifted = 0
        declare_condition(
            claim, kind=LatentCondition.Kind.ASSET_APPEARS, subject="intruder",
            description="holds only while nothing named intruder is on the deployment.",
            declared_by=_person("declarer"),
        )

    def claim(self):
        return AssuranceClaim.objects.filter(deployment=self.dep, claim_type=ClaimType.EFFECTIVE_ACCESS).current().first()

    def world(self, op, arg):
        dep = self.dep
        if op == "drift":
            self.drifted += 1
            Asset.objects.create(
                deployment=dep, kind=Asset.Kind.AGENT, name=f"a{self.drifted}", identifier=f"a{self.drifted}",
                classification=Asset.Classification.APPROVED, metadata={"tools": []},
            )
            check_invalidations(dep)
        elif op == "undrift":
            Asset.objects.filter(deployment=dep, kind=Asset.Kind.AGENT, identifier__regex=r"^a\d+$").delete()
            check_invalidations(dep)
        elif op == "derive":
            derive_claims(dep)
        elif op == "fire":
            if not Asset.objects.filter(deployment=dep, name="intruder").exists():
                Asset.objects.create(deployment=dep, kind=Asset.Kind.DATA_STORE, name="intruder", identifier="intruder")
            evaluate_conditions(dep)
        elif op == "clear":
            Asset.objects.filter(deployment=dep, name="intruder").delete()
            evaluate_conditions(dep)
        elif op == "restore":
            restore_fired_holds(dep)
        elif op == "person":
            claim = self.claim()
            if claim is None:
                return "none"
            try:
                apply_claim_transition(claim, arg, actor=_person(), note="p")
                return "ok"
            except IllegalClaimTransition:
                return "refused"
        return ""

    def evidence(self, op, rng):
        claim = self.claim()
        if claim is None or not ea._is_audited(claim):
            return "skip"
        items = list(ea.evidence_for(claim))
        live_fails = [i for i in items if i.outcome == V.FAIL and i.superseded_by_id is None and i.invalidated_at is None]
        now = timezone.now()
        if op == "fail":
            _record(claim, outcome=V.FAIL.value)
        elif op == "pass":
            _record(claim, outcome=V.PASS.value)
        elif op == "target_fail":
            _record(claim, outcome=V.FAIL.value, origin=Origin.TARGET.value)
        elif op == "stale_fail":
            _record(claim, outcome=V.FAIL.value, observed_at=now - timedelta(days=90), expires_at=now - timedelta(days=1))
        elif op in ("pass_succ", "null_succ", "fail_succ"):
            if not live_fails:
                return "skip"
            outcome = {"pass_succ": V.PASS, "null_succ": V.INSUFFICIENT_EVIDENCE, "fail_succ": V.FAIL}[op].value
            ea.record_claim_evidence(
                claim, supersedes=rng.choice(live_fails),
                **_good(claim, outcome=outcome, observed_at=now - timedelta(seconds=30)),
            )
        elif op == "inval":
            candidates = [i for i in items if i.invalidated_at is None]
            if not candidates:
                return "skip"
            ea.invalidate_claim_evidence(rng.choice(candidates), actor=_person("invalidator"), reason="fuzz")
        return "ok"


class _Rollback(Exception):
    pass


def _fuzz_one(seed):
    """One seed: a violation ``(seed, what, trace, control, hostile)`` or None."""
    rng = random.Random(seed)
    principals = rng.random() < 0.5
    control = _World(f"ctl{seed}", principals)
    hostile = _World(f"hos{seed}", principals)
    trace = []
    for _ in range(_FUZZ_LENGTH):
        if rng.random() < 0.45:
            op = rng.choice(_EVIDENCE_OPS)
            trace.append(f"{op}:{hostile.evidence(op, rng)}")
        else:
            op = rng.choice(_WORLD_OPS)
            arg = rng.choice(_PEOPLE) if op == "person" else None
            trace.append(f"{op}({arg or ''}):{control.world(op, arg)}/{hostile.world(op, arg)}")
        a, b = control.claim(), hostile.claim()
        if a is None or b is None or a.status == Status.REVOKED:
            # A withdrawal is compared with nothing: the control has left the field.
            continue
        bad = []
        if b.status != Status.REVOKED and ea.rank(b.status) > ea.rank(a.status):
            bad.append("rank")
        if _conf(b.confidence) > _conf(a.confidence):
            bad.append("confidence")
        if bad:
            return seed, bad, trace, (a.status, a.confidence), (b.status, b.confidence)
    return None


def test_no_sequence_of_evidence_lifts_a_claim_above_its_no_evidence_control():
    """The round-2 differential fuzz, bounded: 200 seeds of 14 moves each. Both
    deployments get the same drift, re-derives, latent firings, restores and
    person transitions; only the hostile one also gets evidence -- failures,
    passes, successors of every kind, target-authored and stale failures, and
    attributed invalidations. After every move the hostile claim sits no higher
    than the control in status rank or in confidence."""
    violations = []
    for seed in range(_FUZZ_SEEDS):
        try:
            with transaction.atomic():
                found = _fuzz_one(seed)
                raise _Rollback(found)
        except _Rollback as rolled:
            found = rolled.args[0]
        if found is not None:
            violations.append(found)
    assert violations == [], "\n".join(
        f"seed={s} {what}: {' -> '.join(trace)}; control={c} hostile={h}" for s, what, trace, c, h in violations[:5]
    )


# ---------------------------------------------------------------------------
# 4. An unattributed invalidation can be made attributed
# ---------------------------------------------------------------------------


def test_an_attributed_invalidation_attaches_to_an_item_whose_earlier_invalidation_nobody_is_attributed_with():
    """N4. An item stamped invalidated with nobody attributed retires nothing --
    and invalidate_claim_evidence refused it as "already invalidated", so nothing
    could ever retire it: a permanent hold."""
    dep = _deployment("n4")
    claim = _access_claim(dep, principals=False)
    apply_claim_transition(claim, Status.SUPPORTED, actor=_person(), note="reviewed")
    claim.refresh_from_db()
    fail = _record(claim, outcome=V.FAIL.value)
    gone = _person("gone-admin")
    ClaimEvidence.objects.filter(pk=fail.pk).update(
        invalidated_at=timezone.now(), invalidation_reason="probe hit staging", invalidated_by=gone
    )
    gone.delete()
    fail.refresh_from_db()
    ea.audit_claim(claim)
    claim.refresh_from_db()
    assert claim.status == Status.CONTRADICTED

    fresh = _person("fresh-admin")
    ea.invalidate_claim_evidence(fail, actor=fresh, reason="re-invalidating, attributed")
    fail.refresh_from_db()
    claim.refresh_from_db()
    assert fail.invalidated_by_username == fresh.username
    assert "re-invalidating, attributed" in fail.invalidation_reason
    assert claim.status == Status.SUPPORTED
    event = ea.evidence_record(fail)["claim"]["invalidation_events"][0]
    assert event["attributed"] is True and event["by"] == fresh.username

    # An attributed invalidation stands: it is not re-attributed.
    with pytest.raises(ea.EvidenceRefused, match="already invalidated"):
        ea.invalidate_claim_evidence(fail, actor=_person("another"), reason="mine now")
    fail.refresh_from_db()
    assert fail.invalidated_by_username == fresh.username


# ---------------------------------------------------------------------------
# 5. A stored audit a stop did not re-run is never served as the verdict
# ---------------------------------------------------------------------------


def _reads(claim):
    client = APIClient()
    client.force_authenticate(user=_person("reader"))
    detail = client.get(f"/api/assurance/claims/{claim.uuid}/").json()
    evidence = client.get(f"/api/assurance/claims/{claim.uuid}/evidence/").json()
    return detail, evidence


@pytest.mark.parametrize("stop", [Status.CONTRADICTED, Status.REVOKED])
def test_the_audit_a_stop_did_not_re_run_is_marked_not_current_and_is_not_the_verdict(stop):
    """N5. After a stop the claim detail and the evidence read served the pre-stop
    audit -- verdict pass, the item load-bearing -- beside the new status, and for a
    withdrawal nothing ever re-runs it."""
    claim = _access_claim(_deployment(f"n5-{stop}"))
    _record(claim, outcome=V.PASS.value)
    detail, evidence = _reads(claim)
    assert detail["evidence_verdict"] == V.PASS and detail["evidence_audit"]["audit_current"] is True
    assert evidence["evidence_verdict"] == V.PASS and evidence["evidence_audit"]["audit_current"] is True

    apply_claim_transition(claim, stop, actor=_person("stopper"), note="stop")
    detail, evidence = _reads(claim)
    assert detail["status"] == stop
    for read in (detail, evidence):
        assert read["evidence_verdict"] is None
        assert read["evidence_audit"]["audit_current"] is False
        assert read["evidence_audit"]["not_current_reason"]
    assert all(item["weighed"]["audit_current"] is False for item in evidence["evidence"])


def test_a_contested_claim_contradicted_by_a_person_does_not_serve_the_held_audit_as_its_verdict():
    claim = _access_claim(_deployment("n5-contested"))
    _record(claim, outcome=V.FAIL.value)
    assert claim.evidence_verdict == V.CONTESTED
    apply_claim_transition(claim, Status.CONTRADICTED, actor=_person("stopper"), note="stop")
    detail, evidence = _reads(claim)
    assert detail["status"] == Status.CONTRADICTED
    assert detail["evidence_verdict"] is None and evidence["evidence_verdict"] is None
    assert detail["evidence_audit"]["audit_current"] is False
    assert ea.reading_status(AssuranceClaim.objects.get(pk=claim.pk)) == Status.CONTRADICTED

    # The next audit brings it current.
    derive_claims(claim.deployment)
    detail, _ = _reads(_current(claim.deployment))
    assert detail["status"] == Status.CONTRADICTED
    assert detail["evidence_audit"]["audit_current"] is True and detail["evidence_verdict"] is not None


# ---------------------------------------------------------------------------
# 6. The evidence read's offset is bounded
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "offset",
    [str(2**63), str(2**63 - 1), "9" * 30, " 1", "1 ", "+1", "1_0", "١", "-1", "1.0", "", "0x1"],
)
def test_an_evidence_offset_that_is_not_a_bounded_plain_integer_is_a_400(offset):
    """N6. ``int()`` took ``" 1"``, ``"1_0"`` and non-ASCII digits, and an offset past
    2**63 reached the database and raised IntegrityError (a 500)."""
    claim = _access_claim(_deployment("n6"), principals=False)
    _record(claim)
    client = APIClient()
    client.force_authenticate(user=_person("reader"))
    response = client.get(f"/api/assurance/claims/{claim.uuid}/evidence/", {"offset": offset})
    assert response.status_code == 400, (offset, response.status_code)
    assert "offset" in response.json()["detail"]


def test_an_evidence_offset_at_its_bound_is_read_and_past_the_end_returns_nothing():
    from assurance.views import ClaimViewSet

    claim = _access_claim(_deployment("n6-bound"), principals=False)
    _record(claim)
    client = APIClient()
    client.force_authenticate(user=_person("reader"))
    url = f"/api/assurance/claims/{claim.uuid}/evidence/"
    body = client.get(url, {"offset": str(ClaimViewSet.EVIDENCE_MAX_OFFSET)}).json()
    assert body["returned"] == 0 and body["evidence_count"] == 1
    assert client.get(url, {"offset": str(ClaimViewSet.EVIDENCE_MAX_OFFSET + 1)}).status_code == 400
    assert client.get(url, {"offset": "0"}).json()["returned"] == 1
