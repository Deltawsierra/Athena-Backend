"""SPINE #333 -- the verdict / evidence audit: what recorded evidence may do to a claim.

Evidence that is target-authored, stale, contradictory, about another subject, or
warranted only by a signature can never upgrade a claim. Each hostile class below
is set against a MINIMAL PAIR: the same item with the one hostile property removed
carries weight, so each test fails if the one rule that refuses it is deleted.

1. Target-authored evidence is recorded and never load-bearing -- not for a pass,
   and not to retire an independent contradiction by filing over it.
2. Stale evidence (expired, taken against inputs that have since moved) cannot
   prop a claim up; stale ADVERSE evidence degrades it toward incomplete, and a
   contradiction is not shed when a re-derive opens a new version.
3. Contradictory load-bearing evidence is CONTESTED: the claim is held, the
   contradiction recorded, and neither a re-derive nor a person can pick the
   favourable reading -- only an attributed invalidation resolves it.
4. Evidence naming another deployment, claim, component or served route, or no
   subject at all, cannot upgrade the claim.
5. A verified signature is provenance, not truth: without an independent state
   check -- and a "check" that is the record's own digest is not one -- an item
   carries no weight.
6. Attribution keeps account / device / organisation / person apart; a signed
   commit or a service account's action is a traceable artifact, never proof of a
   person's intent.
7. INSUFFICIENT_EVIDENCE is a first-class terminal answer that round-trips through
   the record (store -> read -> serialize -> API) as itself.

And the audit never lifts a claim: a PASS is agreement, not a promotion.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from assurance import evidence_audit as ea
from assurance.claims import IllegalClaimTransition, apply_claim_transition, derive_claims
from assurance.decision import claim_decision_signal
from assurance.models import (
    Asset,
    AssuranceClaim,
    ClaimEvent,
    ClaimEvidence,
    ClaimVerdict,
    Deployment,
    EvidenceClass,
)
from assurance.serializers import AssuranceClaimSerializer, ClaimEventSerializer, ClaimEvidenceSerializer
from assurance.served_route import serving_route_now
from assurance.views import ClaimViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
Origin = ClaimEvidence.Origin
V = ClaimVerdict


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ADMIN)


def _deployment(name="d"):
    return Deployment.objects.create(name=name, owner=_user(f"owner-{name}"))


def _access_claim(dep, *, principals=True):
    """The deployment's EFFECTIVE_ACCESS claim as the deriver reads it: VERIFIED
    (configuration verified, least privilege) with principals, UNKNOWN without."""
    if principals:
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
            classification=Asset.Classification.APPROVED, metadata={"tools": ["reporter"]},
        )
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name="reporter", identifier="reporter",
            classification=Asset.Classification.APPROVED, metadata={"permissions": ["query"]},
        )
    else:
        Asset.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt")
    derive_claims(dep)
    return _current(dep)


def _current(dep, claim_type=ClaimType.EFFECTIVE_ACCESS):
    return AssuranceClaim.objects.filter(deployment=dep, claim_type=claim_type).current().get()


def _good(claim, **over):
    """An evidence item that carries weight against ``claim``: independent,
    live, naming exactly this claim, and backed by an independent state check.
    Every hostile case below is this with ONE thing changed."""
    now = timezone.now()
    kw = dict(
        outcome=V.PASS.value,
        origin=Origin.INDEPENDENT.value,
        evidence_class=EvidenceClass.TECHNICALLY_VERIFIED.value,
        subject_deployment=str(claim.deployment.uuid),
        subject_claim_type=claim.claim_type,
        subject_asset="",
        subject_route=serving_route_now(claim.deployment),
        subject_inputs=claim.input_fingerprint,
        observed_at=now - timedelta(minutes=2),
        state_check_ref="achilles:reach-probe/run-4411",
        state_checked_at=now - timedelta(minutes=1),
        signer="athena-scan-key-1",
        signature_verified=True,
        content_digest="sha256:7f3a9c",
        actor_account="athena-scanner",
        actor_account_kind=ClaimEvidence.AccountKind.SERVICE_ACCOUNT.value,
        actor_device="runner-eu-3",
        actor_organization="Mythos assessor",
        residual_uncertainty=["probe covered read paths only"],
    )
    kw.update(over)
    return kw


def _record(claim, **over):
    item = ea.record_claim_evidence(claim, **_good(claim, **over))
    claim.refresh_from_db()
    return item


def _refused(claim, item):
    for entry in claim.evidence_audit["refused"]:
        if entry["uuid"] == str(item.uuid):
            return entry["reasons"]
    return None


def _admitted(claim, item):
    return any(e["uuid"] == str(item.uuid) for e in claim.evidence_audit["admitted"])


# ---------------------------------------------------------------------------
# The control: what carries weight, and that even it never lifts a claim
# ---------------------------------------------------------------------------


def test_independent_checked_evidence_is_load_bearing_but_never_promotes_the_claim():
    claim = _access_claim(_deployment(), principals=False)
    assert claim.status == Status.UNKNOWN and claim.confidence is None

    item = _record(claim)

    assert _admitted(claim, item)
    assert claim.evidence_verdict == V.PASS
    # A PASS is the evidence agreeing; it is not a promotion. Upward moves stay with
    # the deriver's reading and an attributed person.
    assert claim.status == Status.UNKNOWN
    assert claim.confidence is None


def test_independent_failure_contradicts_a_claim_that_read_unknown():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, outcome=V.FAIL.value)

    assert _admitted(claim, item)
    assert claim.evidence_verdict == V.FAIL
    assert claim.status == Status.CONTRADICTED
    audit_event = claim.events.order_by("-pk").first()
    assert audit_event.cause == ClaimEvent.CAUSE_EVIDENCE_AUDIT and audit_event.actor_id is None


# ---------------------------------------------------------------------------
# 1. Target-authored evidence
# ---------------------------------------------------------------------------


def test_target_authored_evidence_cannot_raise_status_verdict_or_confidence():
    claim = _access_claim(_deployment(), principals=False)
    # Everything else about it is what carries weight: signed, verified, checked.
    item = _record(claim, origin=Origin.TARGET.value)

    assert _refused(claim, item) == [ea.TARGET_AUTHORED]
    assert claim.evidence_verdict == V.INSUFFICIENT_EVIDENCE
    assert claim.status == Status.UNKNOWN
    assert claim.confidence is None
    # Recorded, not dropped.
    assert ClaimEvidence.objects.filter(pk=item.pk).exists()


@pytest.mark.parametrize("origin", [Origin.OPERATOR.value, Origin.VENDOR.value, Origin.UNKNOWN.value])
def test_evidence_from_no_independent_observer_is_not_load_bearing(origin):
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, origin=origin)
    assert _refused(claim, item) == [ea.NOT_INDEPENDENT]
    assert claim.evidence_verdict == V.INSUFFICIENT_EVIDENCE
    assert claim.status == Status.UNKNOWN


def test_a_target_authored_successor_cannot_retire_an_independent_contradiction():
    claim = _access_claim(_deployment())
    assert claim.status == Status.VERIFIED
    contradiction = _record(claim, outcome=V.FAIL.value)
    assert claim.evidence_verdict == V.CONTESTED and claim.status == Status.UNKNOWN

    # The target files a pass OVER the contradiction.
    ea.record_claim_evidence(claim, **_good(claim, origin=Origin.TARGET.value), supersedes=contradiction)
    claim.refresh_from_db()

    assert ea.SUPERSEDED not in (_refused(claim, contradiction) or [])
    assert _admitted(claim, contradiction)
    assert claim.evidence_verdict == V.CONTESTED
    assert claim.status == Status.UNKNOWN


def test_an_independent_successor_does_retire_what_it_supersedes():
    """The minimal pair of the test above: the same supersession by a successor
    that carries weight retires the old item."""
    claim = _access_claim(_deployment())
    contradiction = _record(claim, outcome=V.FAIL.value)
    ea.record_claim_evidence(claim, **_good(claim), supersedes=contradiction)
    claim.refresh_from_db()

    assert ea.SUPERSEDED in _refused(claim, contradiction)
    assert claim.evidence_verdict == V.PASS
    assert claim.status == Status.VERIFIED


# ---------------------------------------------------------------------------
# 2. Stale evidence
# ---------------------------------------------------------------------------


def test_expired_evidence_cannot_prop_a_claim_up_and_reads_incomplete():
    claim = _access_claim(_deployment(), principals=False)
    now = timezone.now()
    item = _record(
        claim, observed_at=now - timedelta(days=200), state_checked_at=now - timedelta(days=200),
        expires_at=now - timedelta(days=110),
    )
    assert _refused(claim, item) == [ea.EXPIRED]
    assert claim.evidence_verdict == V.INCOMPLETE
    assert claim.status == Status.UNKNOWN


def test_evidence_with_no_observation_instant_is_not_live():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, observed_at=None)
    assert ea.NO_OBSERVATION_INSTANT in _refused(claim, item)
    assert claim.evidence_verdict != V.PASS


def test_stale_adverse_evidence_degrades_toward_incomplete_never_to_pass():
    claim = _access_claim(_deployment())
    assert claim.status == Status.VERIFIED
    now = timezone.now()
    item = _record(
        claim, outcome=V.FAIL.value, observed_at=now - timedelta(days=200),
        state_checked_at=now - timedelta(days=200), expires_at=now - timedelta(days=110),
    )
    # Not proof of failure (it is stale), and not dismissed either.
    assert _refused(claim, item) == [ea.EXPIRED]
    assert claim.evidence_verdict == V.INCOMPLETE
    assert claim.status == Status.UNKNOWN
    assert claim.confidence is None


def test_a_contradiction_that_expires_keeps_the_claim_incomplete():
    claim = _access_claim(_deployment())
    now = timezone.now()
    item = _record(claim, outcome=V.FAIL.value, expires_at=now + timedelta(minutes=5))
    assert claim.evidence_verdict == V.CONTESTED

    ea.audit_claim(claim, now=now + timedelta(minutes=10))
    claim.refresh_from_db()
    assert _refused(claim, item) == [ea.EXPIRED]
    assert claim.evidence_verdict == V.INCOMPLETE
    assert claim.status == Status.UNKNOWN


def test_a_new_version_does_not_shed_the_contradiction_recorded_against_the_last():
    dep = _deployment()
    claim = _access_claim(dep)
    item = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.UNKNOWN

    # The inputs this claim rests on move; the deriver still reads VERIFIED.
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="lookup", identifier="lookup",
        classification=Asset.Classification.APPROVED, metadata={"permissions": ["query"]},
    )
    counts = derive_claims(dep)
    new = _current(dep)

    assert counts["superseded"] >= 1 and new.pk != claim.pk
    # Taken against inputs that have moved: it cannot hold the new version as a
    # contradiction, and the new version cannot pass over it either.
    assert ea.TAKEN_AGAINST_OTHER_INPUTS in _refused(new, item)
    assert new.evidence_verdict == V.INCOMPLETE
    assert new.status == Status.UNKNOWN
    assert new.confidence is None


# ---------------------------------------------------------------------------
# 3. Contradictory evidence
# ---------------------------------------------------------------------------


def test_contradictory_load_bearing_evidence_is_contested_never_the_favourable_reading():
    claim = _access_claim(_deployment(), principals=False)
    for_ = _record(claim)
    against = _record(claim, outcome=V.FAIL.value, state_check_ref="athena:egress-probe/run-9")

    assert _admitted(claim, for_) and _admitted(claim, against)
    assert claim.evidence_verdict == V.CONTESTED
    assert claim.status == Status.UNKNOWN
    text = " ".join(claim.evidence_audit["contradictions"])
    assert str(for_.uuid) in text and str(against.uuid) in text


def test_a_contested_claim_is_held_and_a_re_derive_does_not_resolve_it():
    dep = _deployment()
    claim = _access_claim(dep)
    _record(claim, outcome=V.FAIL.value)
    assert claim.evidence_verdict == V.CONTESTED
    assert claim.status == Status.UNKNOWN and claim.confidence is None
    events = claim.events.count()

    counts = derive_claims(dep)
    again = _current(dep)
    assert counts["superseded"] == 0
    assert again.pk == claim.pk
    assert again.status == Status.UNKNOWN
    assert again.evidence_verdict == V.CONTESTED
    assert again.confidence is None
    # Held in place, not churned into a new version or a new event per derive.
    derive_claims(dep)
    assert _current(dep).events.count() == events
    # The hold reaches the decision through the claim it holds.
    assert again.pk in {c.pk for c in claim_decision_signal(dep)["unknown"]}


def test_a_contradicted_claim_is_contested_by_passing_evidence_not_lifted_by_it():
    """The contest runs both ways, and holding means never lifting: a claim the
    deriver reads CONTRADICTED stays CONTRADICTED when independent evidence reads
    pass -- CONTESTED is recorded, and the claim is not raised to UNKNOWN."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
        classification=Asset.Classification.APPROVED, metadata={"tools": ["shell-tool"]},
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell-tool",
        classification=Asset.Classification.APPROVED, metadata={"permissions": ["exec"]},
    )
    derive_claims(dep)
    claim = _current(dep)
    assert claim.status == Status.CONTRADICTED

    item = _record(claim)
    assert _admitted(claim, item)
    assert claim.evidence_verdict == V.CONTESTED
    assert claim.status == Status.CONTRADICTED
    derive_claims(dep)
    assert _current(dep).status == Status.CONTRADICTED

    # Stale adverse evidence does not lift it either.
    now = timezone.now()
    _record(claim, outcome=V.INCOMPLETE.value, expires_at=now - timedelta(days=1))
    assert claim.status == Status.CONTRADICTED


@pytest.mark.parametrize("to_status", [Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED])
def test_a_person_cannot_choose_the_favourable_reading_over_a_contradiction(to_status):
    """A person cannot choose a HIGHER reading than the claim has under an evidence
    hold. Until round 2 this test also refused SUPPORTED and PARTIALLY_VERIFIED on
    a contested VERIFIED claim: readings BELOW its own, not the favourable ones.
    Refusing them kept VERIFIED under the hold, and a release lifted the claim
    above a control that took the downgrade; a downgrade is now recorded as the
    reading under the hold (tests/test_a_person_under_an_evidence_hold.py)."""
    claim = _access_claim(_deployment())
    _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.UNKNOWN  # contested: held below its VERIFIED reading

    # Asking for the reading it already has under the hold asks only for a release.
    with pytest.raises(IllegalClaimTransition, match="Resolve the evidence"):
        apply_claim_transition(claim, Status.VERIFIED, actor=_user("hopeful"), note="release it")

    # A person lowers the reading: accepted. The failure now stands alone, and holds
    # the claim lower still.
    apply_claim_transition(claim, Status.UNKNOWN, actor=_user("doubter"), note="less sure now")
    claim.refresh_from_db()
    held_at = claim.status
    assert ea.rank(held_at) <= ea.rank(Status.UNKNOWN)
    assert ea.reading_status(claim) == Status.UNKNOWN

    # And cannot then choose a higher one over the failure.
    with pytest.raises(IllegalClaimTransition, match="Resolve the evidence"):
        apply_claim_transition(claim, to_status, actor=_user("reviewer"), note="looks fine to me")
    claim.refresh_from_db()
    assert claim.status == held_at
    assert ea.reading_status(claim) == Status.UNKNOWN


def test_a_person_may_always_withdraw_a_contested_claim():
    claim = _access_claim(_deployment())
    _record(claim, outcome=V.FAIL.value)
    apply_claim_transition(claim, Status.REVOKED, actor=_user("reviewer"), note="out of scope")
    claim.refresh_from_db()
    assert claim.status == Status.REVOKED


def test_only_an_attributed_invalidation_resolves_a_contradiction():
    claim = _access_claim(_deployment())
    against = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.UNKNOWN

    with pytest.raises(ea.EvidenceRefused):
        ea.invalidate_claim_evidence(against, actor=None, reason="wrong probe")
    with pytest.raises(ea.EvidenceRefused):
        ea.invalidate_claim_evidence(against, actor=_user("reviewer"), reason="  ")

    reviewer = _user("reviewer2")
    ea.invalidate_claim_evidence(against, actor=reviewer, reason="the probe hit a staging host")
    claim.refresh_from_db()
    assert ea.INVALIDATED in _refused(claim, against)
    # Back to the claim's own reading -- never above it.
    assert claim.status == Status.VERIFIED
    assert claim.evidence_verdict == V.PASS
    record = ea.evidence_record(ClaimEvidence.objects.get(pk=against.pk))
    assert record["claim"]["invalidation_events"][0]["by"] == reviewer.username


def test_a_persons_status_held_by_evidence_is_still_the_persons_when_the_hold_lifts():
    """The audit's hold is not a move of the reading. A person's SUPPORTED that
    load-bearing failure holds at CONTRADICTED stays the person's through a
    re-derive, and is what the claim returns to once the failure is invalidated --
    not superseded into the deriver's UNKNOWN because the audit moved last."""
    dep = _deployment()
    claim = _access_claim(dep, principals=False)
    person = _user("reviewer")
    apply_claim_transition(claim, Status.SUPPORTED, actor=person, note="looks fine to me")
    against = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED and claim.evidence_verdict == V.FAIL

    derive_claims(dep)
    held = _current(dep)
    assert held.pk == claim.pk and held.status == Status.CONTRADICTED

    ea.invalidate_claim_evidence(against, actor=person, reason="probe ran against staging")
    derive_claims(dep)
    after = _current(dep)
    assert after.pk == claim.pk
    assert after.status == Status.SUPPORTED


# ---------------------------------------------------------------------------
# 4. Wrong-subject evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("subject_deployment", "00000000-0000-0000-0000-000000000000", ea.NAMES_ANOTHER_DEPLOYMENT),
        ("subject_deployment", "", ea.NAMES_NO_SUBJECT),
        ("subject_claim_type", ClaimType.DATA_BOUNDARY.value, ea.NAMES_ANOTHER_CLAIM),
        ("subject_claim_type", "", ea.NAMES_NO_SUBJECT),
        ("subject_asset", "11111111-1111-1111-1111-111111111111", ea.NAMES_ANOTHER_COMPONENT),
        ("subject_route", "f" * 64, ea.NAMES_ANOTHER_SERVED_ROUTE),
        ("subject_route", "", ea.NAMES_NO_SERVED_ROUTE),
        ("subject_inputs", "e" * 64, ea.TAKEN_AGAINST_OTHER_INPUTS),
        ("subject_inputs", "", ea.NAMES_NO_INPUTS),
    ],
)
def test_wrong_subject_evidence_cannot_upgrade_the_claim(field, value, reason):
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, **{field: value})

    assert _refused(claim, item) == [reason]
    assert claim.evidence_verdict in (V.INSUFFICIENT_EVIDENCE, V.INCOMPLETE)
    assert claim.status == Status.UNKNOWN
    assert claim.confidence is None


def test_evidence_about_another_deployment_neither_lifts_nor_holds_this_one():
    claim = _access_claim(_deployment())
    other = _deployment("other")
    item = _record(claim, outcome=V.FAIL.value, subject_deployment=str(other.uuid))
    assert _refused(claim, item) == [ea.NAMES_ANOTHER_DEPLOYMENT]
    entry = next(e for e in claim.evidence_audit["refused"] if e["uuid"] == str(item.uuid))
    assert entry["weighs"] == "nothing"
    assert claim.status == Status.VERIFIED


# ---------------------------------------------------------------------------
# 5. Cryptographic integrity is not proof of truth
# ---------------------------------------------------------------------------


def test_a_valid_signature_without_an_independent_state_check_carries_no_weight():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, state_check_ref="", state_checked_at=None)

    assert item.signature_verified is True
    assert _refused(claim, item) == [ea.NO_INDEPENDENT_STATE_CHECK]
    assert claim.evidence_verdict != V.PASS
    assert ea.SIGNATURE_IS_NOT_TRUTH in claim.evidence_audit["residual_uncertainty"]


def test_a_state_check_that_is_the_records_own_digest_is_not_a_state_check():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, state_check_ref="sha256:7f3a9c", content_digest="sha256:7f3a9c")
    assert _refused(claim, item) == [ea.STATE_CHECK_IS_THE_RECORD]
    assert claim.evidence_verdict != V.PASS


def test_a_signed_but_unchecked_failure_cannot_contradict_only_hold_incomplete():
    claim = _access_claim(_deployment())
    item = _record(claim, outcome=V.FAIL.value, state_check_ref="", state_checked_at=None)
    assert _refused(claim, item) == [ea.NO_INDEPENDENT_STATE_CHECK]
    assert claim.evidence_verdict == V.INCOMPLETE
    assert claim.status == Status.UNKNOWN  # held back; not CONTRADICTED on a signature


def test_an_ungraded_item_asserts_nothing():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, evidence_class=EvidenceClass.UNKNOWN.value)
    assert _refused(claim, item) == [ea.UNGRADED]
    assert claim.evidence_verdict != V.PASS


# ---------------------------------------------------------------------------
# 6. Attribution: account / device / organisation / person
# ---------------------------------------------------------------------------


def test_attribution_keeps_account_device_organisation_and_person_apart():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim)
    who = ea.attribution(item)

    assert who["account"] == "athena-scanner"
    assert who["account_kind"] == ClaimEvidence.AccountKind.SERVICE_ACCOUNT
    assert who["device"] == "runner-eu-3"
    assert who["organization"] == "Mythos assessor"
    # A signed record from a service account is a traceable artifact, not a person.
    assert who["signer"] == "athena-scan-key-1" and who["signature_verified"] is True
    assert who["human"] is None
    assert who["reads_as"] == "traceable_artifact"
    assert who["personal_intent"] == "not_established"


def test_a_signed_commit_does_not_name_a_person():
    claim = _access_claim(_deployment(), principals=False)
    with pytest.raises(ea.EvidenceRefused, match="traceable artifact"):
        ea.record_claim_evidence(claim, **_good(claim, actor_human="Dana Operator"))
    with pytest.raises(ea.EvidenceRefused, match="never who was at it"):
        ea.record_claim_evidence(
            claim, **_good(claim, actor_human="Dana Operator", human_identified_by="athena-scan-key-1")
        )
    with pytest.raises(ea.EvidenceRefused, match="never who was at it"):
        ea.record_claim_evidence(
            claim, **_good(claim, actor_human="Dana Operator", human_identified_by="athena-scanner")
        )
    assert not ClaimEvidence.objects.filter(actor_human="Dana Operator").exists()


def test_an_identified_person_is_still_not_proof_of_intent():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(
        claim, actor_account="dana@corp", actor_account_kind=ClaimEvidence.AccountKind.HUMAN_USER.value,
        actor_human="Dana Operator", human_identified_by="in-person review, ticket SEC-118",
    )
    who = ea.attribution(item)
    assert who["human"] == "Dana Operator"
    assert who["reads_as"] == "identified_person"
    assert who["personal_intent"] == "not_established"


def test_a_claim_event_names_the_account_never_a_person():
    claim = _access_claim(_deployment())
    event = apply_claim_transition(claim, Status.CONTRADICTED, actor=_user("svc-bot"), note="n")
    data = ClaimEventSerializer(event).data
    assert data["actor"] == "svc-bot"
    assert data["attribution"] == {
        "kind": "account", "account": "svc-bot", "human": None, "personal_intent": "not_established",
    }


def test_every_evidence_object_binds_all_ten_record_areas():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, areas={"action": {"probe": "reach"}})
    record = ea.evidence_record(item)
    assert tuple(record) == ea.RECORD_AREAS
    assert record["action"] == {"probe": "reach"}
    # Areas nothing recorded read "unknown": present, never absent.
    assert record["execution"] == ea.UNKNOWN and record["repair"] == ea.UNKNOWN
    assert set(record["claim"]) == {"outcome", "conditions", "residual_uncertainty", "expiry", "invalidation_events"}
    assert record["authority"]["integrity_is_not_truth"] == ea.SIGNATURE_IS_NOT_TRUTH
    with pytest.raises(ea.EvidenceRefused):
        ea.record_claim_evidence(claim, **_good(claim, areas={"claim": {"outcome": "pass"}}))


# ---------------------------------------------------------------------------
# 7. INSUFFICIENT_EVIDENCE round-trips as itself
# ---------------------------------------------------------------------------


def test_verdicts_are_disjoint_from_claim_statuses():
    assert not set(V.values) & set(Status.values)


def test_an_item_cannot_carry_contested():
    claim = _access_claim(_deployment(), principals=False)
    with pytest.raises(ea.EvidenceRefused):
        ea.record_claim_evidence(claim, **_good(claim, outcome=V.CONTESTED.value))


def test_insufficient_evidence_round_trips_through_the_record():
    dep = _deployment()
    claim = _access_claim(dep, principals=False)
    _record(claim, origin=Origin.TARGET.value)

    stored = AssuranceClaim.objects.get(pk=claim.pk)
    assert stored.evidence_verdict == "insufficient_evidence"
    assert stored.status == Status.UNKNOWN  # not coerced to contradicted (fail) or a pass

    data = AssuranceClaimSerializer(stored).data
    assert data["evidence_verdict"] == "insufficient_evidence"
    assert data["evidence_verdict_label"] == "Insufficient evidence"
    assert data["evidence_audit"]["verdict"] == "insufficient_evidence"

    # A re-derive keeps the answer as itself.
    derive_claims(dep)
    assert _current(dep).evidence_verdict == "insufficient_evidence"

    # And the API returns it as itself, on the claim and on its evidence.
    factory = APIRequestFactory()
    admin = _user("reader")
    request = factory.get("/x/")
    force_authenticate(request, user=admin)
    detail = ClaimViewSet.as_view({"get": "retrieve"})(request, uuid=str(stored.uuid))
    assert detail.status_code == 200
    assert detail.data["evidence_verdict"] == "insufficient_evidence"
    request = factory.get("/x/")
    force_authenticate(request, user=admin)
    listed = ClaimViewSet.as_view({"get": "evidence"})(request, uuid=str(stored.uuid))
    assert listed.status_code == 200
    assert listed.data["evidence_verdict"] == "insufficient_evidence"
    assert listed.data["evidence"][0]["weighed"] == {
        "load_bearing": False, "reasons": [ea.TARGET_AUTHORED], "weighs": "nothing",
    }


def test_an_insufficient_evidence_item_round_trips_as_itself():
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, outcome=V.INSUFFICIENT_EVIDENCE.value)
    stored = ClaimEvidence.objects.get(pk=item.pk)
    assert stored.outcome == "insufficient_evidence"
    assert ea.evidence_record(stored)["claim"]["outcome"] == "insufficient_evidence"
    assert ClaimEvidenceSerializer(stored).data["outcome"] == "insufficient_evidence"
    # An independent "we could not tell" is load-bearing as exactly that.
    assert _admitted(claim, item)
    assert claim.evidence_verdict == V.INSUFFICIENT_EVIDENCE
    assert claim.status == Status.UNKNOWN


def test_a_claim_with_no_evidence_recorded_has_no_verdict_rather_than_a_guessed_one():
    claim = _access_claim(_deployment())
    assert claim.evidence_verdict == ""
    assert AssuranceClaimSerializer(claim).data["evidence_verdict"] is None


def test_no_route_writes_evidence_the_evidence_read_is_get_only():
    """Evidence is recorded by server code that knows the channel it came in on --
    which is what ``origin``, ``signer`` and ``signature_verified`` state -- never
    by a caller who could simply declare itself independent."""
    claim = _access_claim(_deployment(), principals=False)
    client = APIClient()
    client.force_authenticate(user=_user("poster"))
    url = f"/api/assurance/claims/{claim.uuid}/evidence/"
    assert client.get(url).status_code == 200
    body = _good(claim, observed_at=None, state_checked_at=None)
    for method in (client.post, client.put, client.patch):
        assert method(url, body, format="json").status_code == 405
    assert not ClaimEvidence.objects.exists()
