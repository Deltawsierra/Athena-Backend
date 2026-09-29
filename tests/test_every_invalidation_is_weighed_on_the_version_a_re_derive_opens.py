"""Round 5 (A1-A3, SPINE): an attributed invalidation is weighed on the version a
re-derive opens, whenever it commits.

A re-derive plans outside the write lock and writes only if nothing it read has
moved (round 4). What it compared for the evidence was ``evidence_token``: the
number of items and the highest pk. An invalidation writes no item, so it moved
neither, and the docstring said none was needed -- the invalidation's own audit
would write the claim's row. But that audit is a transaction of its own, run after
the invalidation commits, and it audited the version it had read: a re-derive that
superseded that version in between left the audit nothing to do (``audit_claim``
returned None for a superseded version) and the new version opened from the
evidence as the plan had read it. The lead reproduced, on c59045b (a2: a pass
successor retired a FAIL; the successor is invalidated): the new version read
VERIFIED/pass with ``audit_current`` true while an audit taken then read
UNKNOWN/contested -- the control, the same acts in sequence, read
UNKNOWN/contested. a1 (the invalidated pass still counted in the stored weighing)
and a3 (a hold its only FAIL no longer supports, not released) are the same race.

Now the token counts invalidations (and their attribution, their latest instant,
and successors' marks), so a re-derive whose plan an invalidation overtook plans
that claim again; and an audit whose version was superseded before it ran audits
the identity's CURRENT version.
"""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from django.db import connection
from django.utils import timezone

from assurance import claims as claims_module
from assurance import evidence_audit as ea
from assurance.claims import apply_claim_transition, derive_claims
from assurance.invalidation import check_invalidations
from assurance.models import Asset, AssuranceClaim, ClaimEvidence, ClaimVerdict
from tests.test_every_writer_decides_from_the_row_it_writes import _deployment, _person
from tests.test_spine_evidence_audit import _access_claim, _current, _good

Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict
_OLD_POLICY = "mythos.assurance.policy/0.9+old"


def _supersede_next(claim):
    """The policy pin moves (as after a release): the next re-derive supersedes."""
    AssuranceClaim.objects.filter(pk=claim.pk).update(policy_version=_OLD_POLICY)
    claim.refresh_from_db()


def _setup(dep, shape):
    """A claim with evidence, and the item whose invalidation is the act raced."""
    claim = _access_claim(dep)
    now = timezone.now()
    if shape == "a1":
        # A counted pass beside a counted fail: the pass is invalidated.
        target = ea.record_claim_evidence(claim, **_good(claim, observed_at=now - timedelta(minutes=2)))
        ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value, observed_at=now - timedelta(minutes=1)))
    elif shape == "a2":
        # A pass successor retired a fail: invalidating the successor revives it.
        fail = ea.record_claim_evidence(
            claim, **_good(claim, outcome=V.FAIL.value, observed_at=now - timedelta(minutes=3))
        )
        target = ea.record_claim_evidence(
            claim, supersedes=fail, **_good(claim, observed_at=now - timedelta(minutes=2))
        )
    else:
        # The only item is a counted fail: invalidating it releases the hold.
        target = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    _supersede_next(claim)
    return claim, target


def _weighing(claim):
    return {x["uuid"] for x in ea.stored_weighing(claim).get("admitted", [])}


def _assert_weighed_now(claim, invalidated):
    """The version's stored audit is the audit taken now of the evidence as it is."""
    fresh = ea.audit_of(claim)
    assert (claim.status, claim.evidence_verdict) == (fresh["status"], fresh["verdict"])
    assert ea.served_audit(claim)["audit_current"] is True
    assert _weighing(claim) == {x["uuid"] for x in fresh["admitted"]}
    assert str(invalidated.uuid) not in _weighing(claim)


def _control(shape, person):
    dep = _deployment(f"{shape}-control")
    claim, target = _setup(dep, shape)
    ea.invalidate_claim_evidence(target, actor=person, reason="the probe was mis-scoped")
    derive_claims(dep)
    current = _current(dep)
    return current.status, current.evidence_verdict


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("shape", ["a1", "a2", "a3"])
def test_an_invalidation_committing_while_a_re_derive_is_planned_is_weighed_on_the_version_it_opens(monkeypatch, shape):
    """Thread DERIVE plans a supersede and is parked after its plan; thread INVALIDATE
    commits the invalidation and is parked inside its audit's weighing until the
    re-derive has written. Events only -- no logic is patched."""
    person = _person("inv")
    expected = _control(shape, person)
    dep = _deployment(shape)
    claim, target = _setup(dep, shape)

    invalidated, written = threading.Event(), threading.Event()
    plans = []
    real_plan, real_write, real_audit_of = claims_module._plan_derive, claims_module._write_plan, ea.audit_of

    def plan(deployment, now):
        out = real_plan(deployment, now)
        plans.append(1)
        if len(plans) == 1:
            assert invalidated.wait(20), "the invalidation never committed"
        return out

    def write(plan_):
        out = real_write(plan_)
        written.set()
        return out

    def audit_of(claim_, **kwargs):
        if threading.current_thread().name == "INVALIDATE" and not written.is_set():
            invalidated.set()
            written.wait(20)
        return real_audit_of(claim_, **kwargs)

    monkeypatch.setattr(claims_module, "_plan_derive", plan)
    monkeypatch.setattr(claims_module, "_write_plan", write)
    monkeypatch.setattr(ea, "audit_of", audit_of)
    box: dict = {}

    def run(name, fn):
        def body():
            try:
                box[name] = fn()
            except Exception as exc:  # noqa: BLE001 -- reported by the test
                box[name] = repr(exc)
            finally:
                connection.close()
        return threading.Thread(target=body, name=name)

    derive = run("DERIVE", lambda: derive_claims(dep))
    invalidate = run("INVALIDATE", lambda: ea.invalidate_claim_evidence(
        ClaimEvidence.objects.get(pk=target.pk), actor=person, reason="the probe was mis-scoped"))
    derive.start()
    invalidate.start()
    derive.join(60)
    invalidate.join(60)

    assert isinstance(box.get("DERIVE"), dict) and box["DERIVE"]["superseded"] == 1, box
    assert isinstance(box.get("INVALIDATE"), ClaimEvidence), box
    current = _current(dep)
    assert current.pk != claim.pk
    assert (current.status, current.evidence_verdict) == expected
    _assert_weighed_now(current, target)


@pytest.mark.django_db
@pytest.mark.parametrize("shape", ["a2", "a3"])
def test_an_invalidation_whose_own_audit_never_ran_is_weighed_by_a_re_derive_planned_before_it(monkeypatch, shape):
    """The invalidation commits between the re-derive's plan and its write, and its
    own audit never runs (the worker died after the commit): only the evidence token
    tells the re-derive the evidence moved."""
    person = _person("inv-dropped")
    expected = _control(shape, person)
    dep = _deployment(f"{shape}-dropped")
    claim, target = _setup(dep, shape)
    real_plan = claims_module._plan_derive
    done = []

    def plan(deployment, now):
        out = real_plan(deployment, now)
        if not done:
            done.append(1)
            with monkeypatch.context() as m:
                m.setattr(ea, "audit_claim", lambda *a, **k: None)
                ea.invalidate_claim_evidence(
                    ClaimEvidence.objects.get(pk=target.pk), actor=person, reason="the probe was mis-scoped"
                )
        return out

    monkeypatch.setattr(claims_module, "_plan_derive", plan)
    derive_claims(dep)

    current = _current(dep)
    assert current.pk != claim.pk
    assert (current.status, current.evidence_verdict) == expected
    _assert_weighed_now(current, target)


@pytest.mark.django_db
def test_an_audit_asked_for_a_version_a_re_derive_superseded_weighs_the_identitys_current_version():
    """The invalidation's audit reads the version it recorded against; a re-derive
    superseded it first. That audit returned None and the new version was never
    weighed on the invalidation."""
    dep = _deployment("follow")
    claim, fail = _setup(dep, "a3")
    derive_claims(dep)
    current = _current(dep)
    assert current.pk != claim.pk
    assert current.status == Status.UNKNOWN, "the premise: the new version is held by the fail"
    person = _person("follow")
    # The invalidation committed; its audit, addressed to the version it read, has not run.
    ClaimEvidence.objects.filter(pk=fail.pk).update(
        invalidated_at=timezone.now(), invalidation_reason="the probe was mis-scoped",
        invalidated_by=person, invalidated_by_username=person.username,
    )
    stale_copy = AssuranceClaim.objects.get(pk=claim.pk)

    result = ea.audit_claim(stale_copy)

    assert result is not None and result["verdict"] == V.PASS.value
    assert stale_copy.pk == claim.pk and stale_copy.status == Status.SUPERSEDED
    current.refresh_from_db()
    assert current.status == Status.VERIFIED
    assert current.confidence == 0.88
    _assert_weighed_now(current, fail)


@pytest.mark.django_db
def test_the_evidence_token_moves_on_every_invalidation_attribution_and_successor_mark():
    claim = _access_claim(_deployment("token"))
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    token = lambda: ea.evidence_token(claim.deployment_id, claim.fingerprint)  # noqa: E731
    seen = [token()]

    # A bulk mark nobody is attributed with.
    ClaimEvidence.objects.filter(pk=fail.pk).update(invalidated_at=timezone.now() + timedelta(days=30))
    seen.append(token())
    # Attributed later: stamped now -- earlier than the mark it attributes.
    ea.invalidate_claim_evidence(fail, actor=_person("token"), reason="probe hit staging")
    seen.append(token())
    other = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    seen.append(token())
    ClaimEvidence.objects.filter(pk=other.pk).update(superseded_by=fail)
    seen.append(token())

    assert len(set(seen)) == len(seen), seen


@pytest.mark.django_db
def test_an_item_recorded_between_a_re_derives_plan_and_its_write_holds_the_version_it_opens(monkeypatch):
    """Killer for D2 (the check ignores the evidence token) and E3 (a constant token):
    the FAIL's own audit never runs, so only the token says the evidence moved."""
    dep = _deployment("d2")
    claim = _access_claim(dep)
    _supersede_next(claim)
    real_plan = claims_module._plan_derive
    done = []

    def plan(deployment, now):
        out = real_plan(deployment, now)
        if not done:
            done.append(1)
            with monkeypatch.context() as m:
                m.setattr(ea, "audit_claim", lambda *a, **k: None)
                ea.record_claim_evidence(
                    AssuranceClaim.objects.get(pk=claim.pk), **_good(claim, outcome=V.FAIL.value)
                )
        return out

    monkeypatch.setattr(claims_module, "_plan_derive", plan)
    derive_claims(dep)

    current = _current(dep)
    assert current.pk != claim.pk
    assert current.status == Status.UNKNOWN
    assert current.evidence_verdict == V.CONTESTED.value


@pytest.mark.django_db
def test_an_item_recorded_right_after_the_plan_read_the_items_holds_the_version_it_opens(monkeypatch):
    """Killer for D13 (the plan reads the evidence token AFTER the items): a FAIL
    recorded between the items and a token read after them is in the token and not
    in the items, and the check passes a plan that never weighed it."""
    dep = _deployment("d13")
    claim = _access_claim(dep)
    _supersede_next(claim)
    real_items = claims_module._evidence_by_identity
    done = []

    def items(deployment, *args, **kwargs):
        out = real_items(deployment, *args, **kwargs)
        if not done:
            done.append(1)
            with monkeypatch.context() as m:
                m.setattr(ea, "audit_claim", lambda *a, **k: None)
                ea.record_claim_evidence(
                    AssuranceClaim.objects.get(pk=claim.pk), **_good(claim, outcome=V.FAIL.value)
                )
        return out

    monkeypatch.setattr(claims_module, "_evidence_by_identity", items)
    derive_claims(dep)

    current = _current(dep)
    assert current.status == Status.UNKNOWN
    assert current.evidence_verdict == V.CONTESTED.value


# ---------------------------------------------------------------------------
# Mutant killers on the evidence writers (round 5)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_successor_naming_another_deployments_item_is_refused_and_that_item_stays_live():
    """Killer for E9: an item supersedes only evidence recorded against the same claim."""
    a = _access_claim(_deployment("e9a"))
    b = _access_claim(_deployment("e9b"))
    fail = ea.record_claim_evidence(b, **_good(b, outcome=V.FAIL.value))
    b.refresh_from_db()
    held = (b.status, b.evidence_verdict)

    with pytest.raises(ea.EvidenceRefused, match="same claim"):
        ea.record_claim_evidence(a, supersedes=fail, **_good(a))

    assert ClaimEvidence.objects.get(pk=fail.pk).superseded_by_id is None
    assert not ClaimEvidence.objects.filter(recorded_against=a).exists()
    b.refresh_from_db()
    assert (b.status, b.evidence_verdict) == held


@pytest.mark.django_db
def test_a_drift_under_a_contradicted_hold_reaches_the_reading_and_the_release_lands_on_stale():
    """Killer for E14 (the stale mark stops at the hold): a person's SUPPORTED held at
    CONTRADICTED by a FAIL; the inputs drift; the FAIL is invalidated. The control,
    with no evidence, reads STALE."""
    reads = {}
    for tag, hostile in (("control", False), ("hostile", True)):
        dep = _deployment(f"e14-{tag}")
        claim = _access_claim(dep, principals=False)
        apply_claim_transition(AssuranceClaim.objects.get(pk=claim.pk), Status.SUPPORTED, actor=_person(), note="reviewed")
        claim.refresh_from_db()
        fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value)) if hostile else None
        Asset.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="m2", identifier="m2")
        check_invalidations(dep)
        if fail is not None:
            assert _current(dep).status == Status.CONTRADICTED, "the premise: the fail holds it"
            ea.invalidate_claim_evidence(ClaimEvidence.objects.get(pk=fail.pk), actor=_person(), reason="bad probe")
        current = _current(dep)
        reads[tag] = (current.status, current.confidence)

    assert reads["control"][0] == Status.STALE
    assert reads["hostile"] == reads["control"]


@pytest.mark.django_db
def test_after_a_persons_contradiction_the_stored_pass_is_not_served_as_the_verdict():
    """Killer for E17 (an audit taken at another status served as current)."""
    dep = _deployment("e17")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    assert ea.current_verdict(_current(dep)) == V.PASS.value

    apply_claim_transition(_current(dep), Status.CONTRADICTED, actor=_person(), note="stop")

    current = _current(dep)
    assert current.evidence_verdict == V.PASS.value, "the premise: the stored audit is the pass"
    assert ea.current_verdict(current) is None
    served = ea.served_audit(current)
    assert served["audit_current"] is False
    assert "contradicted" in served["not_current_reason"]

