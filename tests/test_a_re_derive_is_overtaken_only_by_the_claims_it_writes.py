"""Round 5 (D1): a re-derive is overtaken only by a move on a claim it writes, and
then plans again only that claim; its 409 still writes nothing.

A re-derive plans outside the write lock and writes only if nothing it read has
moved (round 4). The check was deployment-wide -- the evidence token over every
item on the deployment, and a plan failed when ANY claim identity's row moved --
and a failed check planned everything again from scratch. With 10,000 items against
the access claim a plan took seconds; a person triaging ANOTHER claim of the
deployment (AI_BOM) every 0.4 s overtook every one of them, and every recompute
ended 409 while a drift the deriver reads as CONTRADICTED (a tool now declares
`shell`) never reached the access claim: it read VERIFIED 0.88 throughout.

Each claim identity's step now carries what it was decided from -- the current
version, the evidence recorded against that identity and every invalidation of it,
and whether a fired condition holds it -- and the check under the lock compares
exactly those, for the identities the plan writes. A step that moved is planned
again alone; the others keep their plan. Past ``DERIVE_ATTEMPTS`` checks it is
``ClaimsKeptMoving`` (409), and nothing was written.

The mutant killers here are the round-5 adversary's (D1, D5, D10, D12, E1/E2).
"""

from __future__ import annotations

import pytest
from django.utils import timezone

from assurance import claims as claims_module
from assurance import evidence_audit as ea
from assurance.claims import ClaimsKeptMoving, apply_claim_transition, derive_claims
from assurance.invalidation import check_invalidations
from assurance.latent import declare_condition, evaluate_conditions
from assurance.models import Asset, AssuranceClaim, ClaimAuditWeighing, ClaimEvent, ClaimEvidence, ClaimVerdict, LatentCondition
from tests.test_every_writer_decides_from_the_row_it_writes import _client, _deployment, _person, _seed
from tests.test_spine_evidence_audit import _access_claim, _current, _good

Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
V = ClaimVerdict
_OLD_POLICY = "mythos.assurance.policy/0.9+old"


def _other(dep):
    return next(c for c in AssuranceClaim.objects.filter(deployment=dep).current() if c.claim_type != ClaimType.EFFECTIVE_ACCESS)


def _triage(dep, claim_type, person):
    """A person's ordinary move on a claim: SUPPORTED and UNKNOWN in turn."""
    row = AssuranceClaim.objects.filter(deployment=dep, claim_type=claim_type).current().get()
    target = Status.SUPPORTED if row.status != Status.SUPPORTED else Status.UNKNOWN
    apply_claim_transition(row, target, actor=person, note="triage")
    return target


def _shell(dep):
    """The tool now declares `shell`: the deriver reads the access claim CONTRADICTED."""
    Asset.objects.filter(deployment=dep, identifier="reporter").update(metadata={"permissions": ["shell"]})


@pytest.mark.django_db
def test_a_person_triaging_another_claim_after_every_plan_never_starves_the_re_derive(monkeypatch):
    """D1's shape, deterministic: after EVERY full plan a person moves the AI_BOM
    claim. On c59045b each plan was overtaken and the recompute ended 409 after
    five; the access claim's drift never landed."""
    dep = _deployment("d1")
    claim = _access_claim(dep)
    _seed(claim, 50)
    other = _other(dep)
    person = _person("triager")
    _shell(dep)
    real_plan = claims_module._plan_derive
    plans, moves = [], []

    def plan(deployment, now):
        out = real_plan(deployment, now)
        plans.append(1)
        moves.append(_triage(dep, other.claim_type, person))
        return out

    monkeypatch.setattr(claims_module, "_plan_derive", plan)
    response = _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/", {}, format="json")

    assert response.status_code == 200, response.content
    assert plans == [1], "the whole deployment was planned again for a move on another claim"
    access = _current(dep)
    assert access.status == Status.CONTRADICTED
    assert access.confidence is None
    # The person's move on the other claim is what it reads: the re-derive planned it
    # again from that move and wrote nothing over it.
    assert _current(dep, other.claim_type).status == moves[-1]
    assert claims_module._status_set_by_a_person(_current(dep, other.claim_type))


@pytest.mark.django_db
def test_a_re_derive_overtaken_at_every_check_stops_after_the_bound_and_writes_nothing(monkeypatch):
    """Killer for D5 (a bound of 50): every check finds a claim it writes moved --
    a person moves the other claim after each plan and each re-plan. Exactly
    DERIVE_ATTEMPTS checks, then 409, and nothing written."""
    dep = _deployment("d5")
    claim = _access_claim(dep)
    other = _other(dep)
    person = _person("triager")
    _shell(dep)
    before = {c.pk: (c.status, c.updated_at) for c in AssuranceClaim.objects.filter(deployment=dep)}
    derive_events = ClaimEvent.objects.filter(claim__deployment=dep, by_person=False).count()
    real_plan, real_again, real_check = claims_module._plan_derive, claims_module._plan_again, claims_module._moved_steps
    checks = []

    def plan(deployment, now):
        out = real_plan(deployment, now)
        _triage(dep, other.claim_type, person)
        return out

    def again(plan_, moved):
        real_again(plan_, moved)
        _triage(dep, other.claim_type, person)

    def check(plan_):
        checks.append(1)
        return real_check(plan_)

    monkeypatch.setattr(claims_module, "_plan_derive", plan)
    monkeypatch.setattr(claims_module, "_plan_again", again)
    monkeypatch.setattr(claims_module, "_moved_steps", check)

    response = _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/", {}, format="json")

    assert response.status_code == 409, response.content
    assert "Nothing was written" in response.json()["detail"]
    assert len(checks) == claims_module.DERIVE_ATTEMPTS == 5
    with pytest.raises(ClaimsKeptMoving):
        monkeypatch.setattr(claims_module, "DERIVE_ATTEMPTS", 2)
        checks.clear()
        derive_claims(dep)
    assert len(checks) == 2
    # Nothing the re-derive decided was written: the access claim is the version it
    # was, as it was; no version opened; no machine event.
    access = _current(dep)
    assert access.pk == claim.pk and (access.status, access.updated_at) == before[claim.pk]
    assert AssuranceClaim.objects.filter(deployment=dep).count() == len(before)
    assert ClaimEvent.objects.filter(claim__deployment=dep, by_person=False).count() == derive_events


@pytest.mark.django_db
def test_a_condition_firing_on_a_stale_claim_between_plan_and_write_keeps_it_held(monkeypatch):
    """Killer for D1 (the check ignores fired conditions): the firing opens a retest
    and writes nothing to a claim already STALE, so no claim token moves -- only the
    fired conditions say the plan is stale."""
    dep = _deployment("k-d1")
    claim = _access_claim(dep)
    declare_condition(
        claim, kind=LatentCondition.Kind.ASSET_APPEARS, subject="intruder",
        description="holds only while nothing named intruder is on the deployment.", declared_by=_person(),
    )
    extra = Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="a1", identifier="a1",
        classification=Asset.Classification.APPROVED, metadata={"tools": []},
    )
    check_invalidations(dep)
    extra.delete()
    assert _current(dep).status == Status.STALE, "the premise: a stale claim"
    real_plan = claims_module._plan_derive
    fired = []

    def plan(deployment, now):
        out = real_plan(deployment, now)
        if not fired:
            fired.append(1)
            Asset.objects.create(deployment=dep, kind=Asset.Kind.DATA_STORE, name="intruder", identifier="intruder")
            evaluate_conditions(dep)
        return out

    monkeypatch.setattr(claims_module, "_plan_derive", plan)
    derive_claims(dep)

    current = _current(dep)
    assert current.fingerprint in claims_module.held_by_fired_conditions(dep)
    assert current.status == Status.STALE


@pytest.mark.django_db
def test_a_same_status_stop_between_plan_and_write_carries_and_outlives_the_drift_back(monkeypatch):
    """Killer for E1 (the claim token drops updated_at) and E2 (a status-only token):
    the deriver already reads CONTRADICTED and a person contradicts it too while a
    supersede is planned -- no status moves, no audit is held; only updated_at and
    the person's event. The stop must carry, and outlive `shell` being dropped."""
    dep = _deployment("k-e1")
    _access_claim(dep)
    _shell(dep)
    derive_claims(dep)
    claim = _current(dep)
    assert claim.status == Status.CONTRADICTED
    AssuranceClaim.objects.filter(pk=claim.pk).update(policy_version=_OLD_POLICY)
    real_plan = claims_module._plan_derive
    done = []

    def plan(deployment, now):
        out = real_plan(deployment, now)
        if not done:
            done.append(1)
            apply_claim_transition(AssuranceClaim.objects.get(pk=claim.pk), Status.CONTRADICTED, actor=_person(), note="confirmed")
        return out

    monkeypatch.setattr(claims_module, "_plan_derive", plan)
    derive_claims(dep)

    current = _current(dep)
    assert current.pk != claim.pk
    assert current.status == Status.CONTRADICTED
    assert current.events.filter(by_person=True, to_status=Status.CONTRADICTED).exists()
    Asset.objects.filter(deployment=dep, identifier="reporter").update(metadata={"permissions": ["query"]})
    derive_claims(dep)
    assert _current(dep).status == Status.CONTRADICTED


@pytest.mark.django_db
@pytest.mark.parametrize("principals", [True, False], ids=["derivers-pass", "persons-supported"])
def test_a_stop_carried_over_a_counted_failure_is_not_lifted_when_the_failure_is_invalidated(principals):
    """Killer for D10 (a carried version's audit is read against the deriver, not the
    stop): the audit then stores the deriver's reading under a hold, and the
    invalidation of the failure releases the claim to it -- the person's stop lifted
    by evidence."""
    dep = _deployment("k-d10")
    claim = _access_claim(dep, principals=principals)
    if not principals:
        apply_claim_transition(AssuranceClaim.objects.get(pk=claim.pk), Status.SUPPORTED, actor=_person(), note="reviewed")
        claim.refresh_from_db()
    fail = ea.record_claim_evidence(claim, **_good(claim, outcome=V.FAIL.value))
    apply_claim_transition(AssuranceClaim.objects.get(pk=claim.pk), Status.CONTRADICTED, actor=_person(), note="take it down")
    AssuranceClaim.objects.filter(pk=claim.pk).update(policy_version=_OLD_POLICY)
    derive_claims(dep)
    carried = _current(dep)
    assert carried.pk != claim.pk and carried.status == Status.CONTRADICTED

    ea.invalidate_claim_evidence(ClaimEvidence.objects.get(pk=fail.pk), actor=_person(), reason="probe hit staging")
    assert _current(dep).status == Status.CONTRADICTED
    derive_claims(dep)
    assert _current(dep).status == Status.CONTRADICTED
    assert ea.reading_status(_current(dep)) == Status.CONTRADICTED


@pytest.mark.django_db
def test_a_re_derive_that_moves_nothing_does_not_write_the_weighing_again():
    """Killer for D12 (the weighing always rewritten): it grows with the evidence."""
    dep = _deployment("k-d12")
    claim = _access_claim(dep)
    ea.record_claim_evidence(claim, **_good(claim))
    derive_claims(dep)
    before = ClaimAuditWeighing.objects.get(claim_id=_current(dep).pk).updated_at

    derive_claims(dep, now=timezone.now())

    assert ClaimAuditWeighing.objects.get(claim_id=_current(dep).pk).updated_at == before
