"""SPINE #333, round 3: the extended differential fuzz, committed and bounded, and a
dedicated test for each hold rule the round-2 tests let a mutant through.

The fuzz (round-3 ``c2_fuzz.py``) runs two identical deployments. Both get the
same world: drift and its undoing, re-derives, a latent condition firing,
clearing, being put back and withdrawn, people's moves, and STOPS (contradict,
revoke) at any point. Only the hostile one also gets evidence: failures, passes,
partial items, successors of every kind (pass, null, fail, over a pass, at the
same instant), target-authored, expired, future and wrong-input items,
attributed invalidations, unattributed invalidation marks and attributions made
of them later. After every move:

- RANK / CONF: the hostile claim is no higher than the control in status rank or
  in confidence (none lowest);
- STOP: a stop is never refused, in either world, and the hostile claim reads the
  stop (or stays withdrawn);
- DOWN: a person's move strictly below the hostile claim's reading is never
  refused over its evidence.

At the end every hostile item is invalidated, attributed, and both re-derived:
STUCK -- a hold no attributed act lifts -- is a violation too.
"""

from __future__ import annotations

import random
from datetime import timedelta
from itertools import count

import pytest
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from assurance import evidence_audit as ea
from assurance.claims import IllegalClaimTransition, apply_claim_transition, derive_claims
from assurance.invalidation import check_invalidations
from assurance.latent import declare_condition, evaluate_conditions, restore_fired_holds, withdraw_condition
from assurance.models import (
    Asset,
    AssuranceClaim,
    ClaimEvidence,
    ClaimVerdict,
    Deployment,
    LatentCondition,
)
from tests.test_spine_evidence_audit import _access_claim, _good

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
Origin = ClaimEvidence.Origin
V = ClaimVerdict
_names = count()

#: Sized to run in well under 90 s on CI (about 40 s on the development machine).
_FUZZ_SEEDS = 60
_FUZZ_LENGTH = 24

_MOVES = [Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED, Status.UNKNOWN, Status.DRAFT]
_STOPS = [Status.CONTRADICTED, Status.REVOKED]
_EVIDENCE_OPS = [
    "fail", "fail", "pass", "pass", "incomplete", "pass_succ", "null_succ", "fail_succ", "succ_over_pass",
    "same_instant_succ", "target_fail", "stale_fail", "wrong_inputs_fail", "future_pass", "expired_pass",
    "inval", "inval", "unattr_mark", "unattr_then_attr",
]
_WORLD_OPS = [
    "drift", "derive", "derive", "fire", "clear", "restore", "withdraw", "person", "person", "person",
    "stop", "undrift", "check",
]


def _person(prefix="p"):
    return User.objects.create_user(username=f"{prefix}-fz3-{next(_names)}", password=None, role=User.Roles.ADMIN)


def _conf(value):
    return -1.0 if value is None else value


class _Rollback(Exception):
    pass


class _World:
    def __init__(self, name, principals):
        self.dep = Deployment.objects.create(name=name, owner=_person("owner"))
        claim = _access_claim(self.dep, principals=principals)
        self.drifted = 0
        declare_condition(
            claim, kind=LatentCondition.Kind.ASSET_APPEARS, subject="intruder",
            description="holds only while nothing named intruder is on the deployment.", declared_by=_person(),
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
        elif op == "check":
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
        elif op == "withdraw":
            condition = LatentCondition.objects.filter(deployment=dep).order_by("-pk").first()
            try:
                withdraw_condition(condition, withdrawn_by=_person(), note="fuzz")
            except Exception as exc:  # noqa: BLE001 -- an already-withdrawn condition is refused; same in both worlds
                return "wd-" + type(exc).__name__
            return "ok"
        elif op in ("person", "stop"):
            claim = self.claim()
            if claim is None:
                return "none"
            try:
                apply_claim_transition(claim, arg, actor=_person(), note="fuzz")
                return "ok"
            except IllegalClaimTransition as exc:
                text = str(exc)
                return "refused" if ("evidence recorded" in text or "Resolve the evidence" in text) else "illegal"
            except Exception as exc:  # noqa: BLE001 -- any other failure of a move is the finding
                return f"EXC-{type(exc).__name__}:{str(exc)[:80]}"
        return ""

    def evidence(self, op, rng):
        claim = self.claim()
        if claim is None or not ea._is_audited(claim):
            return "skip"
        items = list(ea.evidence_for(claim))
        live = [i for i in items if i.superseded_by_id is None and i.invalidated_at is None]
        live_fails = [i for i in live if i.outcome == V.FAIL]
        live_passes = [i for i in live if i.outcome == V.PASS]
        now = timezone.now()

        def rec(supersedes=None, **over):
            ea.record_claim_evidence(claim, supersedes=supersedes, **_good(claim, **over))

        if op == "fail":
            rec(outcome=V.FAIL.value)
        elif op == "pass":
            rec(outcome=V.PASS.value)
        elif op == "incomplete":
            rec(outcome=V.INCOMPLETE.value)
        elif op == "target_fail":
            rec(outcome=V.FAIL.value, origin=Origin.TARGET.value)
        elif op == "stale_fail":
            rec(outcome=V.FAIL.value, observed_at=now - timedelta(days=90), expires_at=now - timedelta(days=1))
        elif op == "wrong_inputs_fail":
            rec(outcome=V.FAIL.value, subject_inputs="0" * 64)
        elif op == "future_pass":
            rec(outcome=V.PASS.value, observed_at=now + timedelta(hours=1))
        elif op == "expired_pass":
            rec(outcome=V.PASS.value, observed_at=now - timedelta(days=90), expires_at=now - timedelta(days=1))
        elif op in ("pass_succ", "null_succ", "fail_succ", "same_instant_succ"):
            if not live_fails:
                return "skip"
            failed = rng.choice(live_fails)
            outcome = {"pass_succ": V.PASS, "null_succ": V.INSUFFICIENT_EVIDENCE, "fail_succ": V.FAIL,
                       "same_instant_succ": V.PASS}[op].value
            observed = failed.observed_at if op == "same_instant_succ" else now - timedelta(seconds=30)
            rec(supersedes=failed, outcome=outcome, observed_at=observed)
        elif op == "succ_over_pass":
            if not live_passes:
                return "skip"
            rec(supersedes=rng.choice(live_passes), outcome=V.FAIL.value, observed_at=now - timedelta(seconds=20))
        elif op == "inval":
            candidates = [i for i in items if i.invalidated_at is None or not ea._attributed_invalidation(i)]
            if not candidates:
                return "skip"
            ea.invalidate_claim_evidence(rng.choice(candidates), actor=_person(), reason="fuzz")
        elif op == "unattr_mark":
            candidates = [i for i in items if i.invalidated_at is None]
            if not candidates:
                return "skip"
            ClaimEvidence.objects.filter(pk=rng.choice(candidates).pk).update(
                invalidated_at=now, invalidation_reason="bulk"
            )
        elif op == "unattr_then_attr":
            candidates = [i for i in items if i.invalidated_at is not None and not ea._attributed_invalidation(i)]
            if not candidates:
                return "skip"
            ea.invalidate_claim_evidence(rng.choice(candidates), actor=_person(), reason="attributing")
        return "ok"


def _check(control, hostile, op, arg, r_control, r_hostile):
    bad = []
    if op == "stop":
        for tag, result in (("control", r_control), ("hostile", r_hostile)):
            if result not in ("ok", "none"):
                bad.append(f"STOP-REFUSED-{tag}:{result}")
        if hostile is not None and r_hostile == "ok" and hostile.status not in (arg, Status.REVOKED):
            bad.append(f"STOP:{hostile.status}")
    if control is None or hostile is None or control.status == Status.REVOKED:
        return bad
    if hostile.status != Status.REVOKED and ea.rank(hostile.status) > ea.rank(control.status):
        bad.append("RANK")
    if _conf(hostile.confidence) > _conf(control.confidence):
        bad.append("CONF")
    return bad


def _fuzz_one(seed):
    rng = random.Random(seed)
    principals = rng.random() < 0.5
    control, hostile = _World(f"c{seed}", principals), _World(f"h{seed}", principals)
    trace = []
    for _step in range(_FUZZ_LENGTH):
        if rng.random() < 0.45:
            op = rng.choice(_EVIDENCE_OPS)
            result = hostile.evidence(op, rng)
            trace.append(f"{op}:{result}")
            arg, r_control, r_hostile = None, "", result
        else:
            op = rng.choice(_WORLD_OPS)
            arg = rng.choice(_MOVES) if op == "person" else (rng.choice(_STOPS) if op == "stop" else None)
            if op == "stop" and rng.random() < 0.85:
                arg = Status.CONTRADICTED  # a withdrawal ends the run's interest; keep it rarer
            before = hostile.claim()
            reading = ea.reading_status(before) if before is not None else None
            r_control = control.world(op, arg)
            r_hostile = hostile.world(op, arg)
            trace.append(f"{op}{'(' + arg + ')' if arg else ''}:{r_control}/{r_hostile}")
            if op == "person" and r_hostile == "refused" and reading and ea.rank(arg) < ea.rank(reading):
                return seed, ["DOWN-REFUSED"], trace
        bad = _check(control.claim(), hostile.claim(), op, arg, r_control, r_hostile)
        if bad:
            return seed, bad, trace
    claim = hostile.claim()
    if claim is not None:
        for item in ea.evidence_for(claim):
            if item.invalidated_at is None or not ea._attributed_invalidation(item):
                ea.invalidate_claim_evidence(item, actor=_person(), reason="resolve")
        derive_claims(control.dep)
        derive_claims(hostile.dep)
        claim = hostile.claim()
        if claim is not None and ea._held_by_audit(claim):
            return seed, ["STUCK"], [*trace, "resolve"]
        bad = _check(control.claim(), claim, "resolve", None, "", "")
        if bad:
            return seed, bad, [*trace, "resolve"]
    return None


def test_no_sequence_with_stops_supersession_and_latent_holds_lifts_a_claim_above_its_control():
    violations = []
    for seed in range(_FUZZ_SEEDS):
        try:
            with transaction.atomic():
                raise _Rollback(_fuzz_one(seed))
        except _Rollback as rolled:
            if rolled.args[0] is not None:
                violations.append(rolled.args[0])
    assert violations == [], "\n".join(f"seed={s} {bad}: {' -> '.join(t)}" for s, bad, t in violations[:5])


# ---------------------------------------------------------------------------
# One test per hold rule a mutant got past (round-3 MN2c, MN2f)
# ---------------------------------------------------------------------------


def _pair(name):
    """Two deployments whose EFFECTIVE_ACCESS claim derives UNKNOWN (no supporting
    confidence), each read SUPPORTED by a person: the person's move carries no
    confidence, so the control stays at none."""
    out = []
    for world in ("control", "hostile"):
        dep = Deployment.objects.create(name=f"{name}-{world}", owner=_person("owner"))
        claim = _access_claim(dep, principals=False)
        apply_claim_transition(claim, Status.SUPPORTED, actor=_person(), note="reviewed")
        claim.refresh_from_db()
        assert claim.confidence is None
        out.append(claim)
    return out


def _move_both(claims, to_status):
    for claim in claims:
        apply_claim_transition(claim, to_status, actor=_person(), note="relabel")
        claim.refresh_from_db()


def test_a_hold_a_persons_move_releases_restores_no_more_confidence_than_the_reading_had():
    """MN2c. Under a hold, a person moves the reading and the evidence taken now no
    longer holds it -- a successor observed ahead of the audit's clock has since
    become admissible and retires the failure. The release lands on the person's
    reading with no more confidence than the reading carried: none, like the
    control. Uncapped, it took the full confidence of the status (a claim with no
    supporting confidence above the control)."""
    control, hostile = _pair("mn2c")
    audited_at = timezone.now() - timedelta(hours=1)
    fail = ea.record_claim_evidence(
        hostile,
        **_good(hostile, outcome=V.FAIL.value, observed_at=audited_at - timedelta(minutes=2),
                state_checked_at=audited_at - timedelta(minutes=1)),
        now=audited_at,
    )
    ea.record_claim_evidence(
        hostile, supersedes=fail,
        **_good(hostile, outcome=V.PASS.value, observed_at=audited_at + timedelta(minutes=30),
                state_checked_at=audited_at + timedelta(minutes=31)),
        now=audited_at,
    )
    hostile.refresh_from_db()
    assert hostile.status == Status.CONTRADICTED and hostile.evidence_audit["held"] is True

    _move_both((control, hostile), Status.PARTIALLY_VERIFIED)

    assert hostile.status == Status.PARTIALLY_VERIFIED
    assert hostile.evidence_audit.get("held") is False
    assert hostile.confidence is None
    assert _conf(hostile.confidence) <= _conf(control.confidence)


def test_a_persons_move_under_a_hold_keeps_the_readings_confidence_as_the_holds_base():
    """MN2f. A person's move recorded under a hold keeps, as the hold's base, the
    confidence the reading had -- none here -- never the confidence of the status
    moved to. The later attributed release restores no more than that."""
    control, hostile = _pair("mn2f")
    fail = ea.record_claim_evidence(hostile, **_good(hostile, outcome=V.FAIL.value))
    hostile.refresh_from_db()
    assert hostile.status == Status.CONTRADICTED

    _move_both((control, hostile), Status.PARTIALLY_VERIFIED)
    assert hostile.status == Status.CONTRADICTED
    assert hostile.evidence_audit["base_status"] == Status.PARTIALLY_VERIFIED
    assert hostile.evidence_audit["base_confidence"] is None

    ea.invalidate_claim_evidence(fail, actor=_person("reviewer"), reason="probe hit staging")
    hostile.refresh_from_db()
    assert hostile.status == Status.PARTIALLY_VERIFIED
    assert hostile.confidence is None
    assert _conf(hostile.confidence) <= _conf(control.confidence)
