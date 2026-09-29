"""SPINE #333, round 1: evidence can hold a claim back, and can never lift it.

After any sequence of evidence recorded, superseded or invalidated -- and of the
other writers that move a claim meanwhile (drift, a fired latent condition, a
re-derive, a person) -- a claim never sits above where it would sit with no
evidence at all, in status rank or in confidence, and a hold is lifted only by an
attributed act. Each test below is one way that failed, set beside its control.

1. A hold does not shelter the reading under it: drift and a fired condition reach
   the reading the hold keeps, so a released hold lands on STALE, not on the
   reading from before the change (check_invalidations, a firing, a re-derive).
2. A successor retires what it supersedes only when it carries weight under the
   full admission rules -- an item that asserts nothing retires nothing.
3. A successor retires only what it observed after: an older observation never
   retires a newer contradiction, and the audit says why.
4. A contradiction is a stop: it does no evidence work before it is written, its
   cost does not grow with the evidence, and no audit failure can refuse it.
5. "The state check is the record's own digest" is judged on the digest, not on
   its spelling.
6. What a load-bearing failure does to a claim is written down, both ways.
7. An invalidation's attribution survives the account, and an invalidation nobody
   is attributed with retires nothing.
8. #343: the evidence class a claim takes from a provider assertion is capped by
   what the assertion's source can prove; a self-declared label never verifies.
9. The evidence read is bounded, and a near-miss subject is never silent.
"""

from __future__ import annotations

import time
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from mythos_core.evidence import strength_from_evidence_class
from rest_framework.test import APIClient

from assurance import evidence_audit as ea
from assurance.claims import apply_claim_transition, derive_claims
from assurance.invalidation import check_invalidations
from assurance.latent import declare_condition, evaluate_conditions
from assurance.models import (
    Asset,
    AssuranceClaim,
    ClaimEvidence,
    ClaimVerdict,
    DataBoundary,
    Deployment,
    EvidenceClass,
    LatentCondition,
    Provider,
    ProviderAssertion,
)
from tests.test_spine_evidence_audit import (
    _access_claim,
    _admitted,
    _current,
    _deployment,
    _good,
    _record,
    _refused,
    _user,
)

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
Origin = ClaimEvidence.Origin
V = ClaimVerdict


def _new_principal(dep, name="a2"):
    """An input the EFFECTIVE_ACCESS claim reads moves: a new principal."""
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name=name, identifier=name,
        classification=Asset.Classification.APPROVED, metadata={"tools": []},
    )


def _person_supported(name):
    """A claim the deriver reads UNKNOWN, which a person moved to SUPPORTED."""
    dep = _deployment(name)
    claim = _access_claim(dep, principals=False)
    apply_claim_transition(claim, Status.SUPPORTED, actor=_user(f"reviewer-{name}"), note="reviewed")
    claim.refresh_from_db()
    return dep, claim


def _supersession(claim, item):
    for entry in claim.evidence_audit.get("supersessions", []):
        if entry["evidence"] == str(item.uuid):
            return entry
    return None


# ---------------------------------------------------------------------------
# 1. A hold does not shelter the reading under it
# ---------------------------------------------------------------------------


def test_drift_reaches_the_reading_under_an_evidence_hold_so_its_release_lands_on_stale():
    """S1. The control drifts to STALE. The same claim held at CONTRADICTED by a
    load-bearing failure used to be skipped by the drift (CONTRADICTED is never
    softened), and invalidating the failure released it to the SUPPORTED it read
    before the drift, with confidence 0.28 -- above the control on both counts."""
    control_dep, control = _person_supported("control")
    _new_principal(control_dep)
    check_invalidations(control_dep)
    control.refresh_from_db()
    assert control.status == Status.STALE

    dep, claim = _person_supported("held")
    fail = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED and claim.evidence_audit["base_status"] == Status.SUPPORTED

    _new_principal(dep)
    check_invalidations(dep)
    claim.refresh_from_db()
    # The hold stands, and the reading under it is now the stale one.
    assert claim.status == Status.CONTRADICTED
    assert claim.evidence_audit["base_status"] == Status.STALE

    ea.invalidate_claim_evidence(fail, actor=_user("releaser"), reason="probe hit staging")
    claim.refresh_from_db()
    assert claim.status == Status.STALE
    assert ea.rank(claim.status) <= ea.rank(control.status)
    assert claim.confidence is None and control.confidence is None


def test_a_fired_latent_condition_reaches_the_reading_under_an_evidence_hold():
    """The latent path marks a fired claim STALE through the same seam, and skipped
    a held CONTRADICTED the same way: the release went back above the firing."""
    dep, claim = _person_supported("latent")
    declare_condition(
        claim, kind=LatentCondition.Kind.ASSET_APPEARS, subject="intruder",
        description="The claim holds only while nothing named intruder is on the deployment.",
        declared_by=_user("counsel"),
    )
    fail = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED

    Asset.objects.create(deployment=dep, kind=Asset.Kind.DATA_STORE, name="intruder", identifier="intruder")
    assert evaluate_conditions(dep)["fired_count"] == 1
    claim.refresh_from_db()
    assert claim.status == Status.CONTRADICTED
    assert claim.evidence_audit["base_status"] == Status.STALE

    ea.invalidate_claim_evidence(fail, actor=_user("releaser"), reason="probe hit staging")
    claim.refresh_from_db()
    assert claim.status == Status.STALE
    assert claim.confidence is None


def test_a_re_derive_under_a_fired_condition_keeps_the_reading_under_an_evidence_hold_stale():
    """A re-derive audits the deriver's reading, and a fired condition holds that
    reading at STALE. The audit used to be read against the deriver's pass and the
    condition applied after it, so the hold stored the pass as its reading and its
    release lifted the claim over a condition that still stands."""
    dep = _deployment("rederive")
    claim = _access_claim(dep)
    assert claim.status == Status.VERIFIED
    declare_condition(
        claim, kind=LatentCondition.Kind.ASSET_APPEARS, subject="intruder",
        description="The claim holds only while nothing named intruder is on the deployment.",
        declared_by=_user("counsel"),
    )
    Asset.objects.create(deployment=dep, kind=Asset.Kind.DATA_STORE, name="intruder", identifier="intruder")
    evaluate_conditions(dep)
    derive_claims(dep)
    control_status = _current(dep).status
    assert control_status == Status.STALE  # the control: held by the condition alone

    held = _current(dep)
    fail = _record(held, outcome=V.FAIL.value)
    assert held.status == Status.CONTRADICTED
    derive_claims(dep)
    held = _current(dep)
    assert held.status == Status.CONTRADICTED
    assert held.evidence_audit["base_status"] == Status.STALE

    ea.invalidate_claim_evidence(fail, actor=_user("releaser"), reason="probe hit staging")
    held.refresh_from_db()
    assert held.status == Status.STALE
    assert ea.rank(held.status) <= ea.rank(control_status)
    assert held.confidence is None


def test_a_released_hold_never_carries_more_confidence_than_the_reading_had():
    """A person's SUPPORTED over a deriver's UNKNOWN carries the strength of its
    evidence class, as the same SUPPORTED carries it with no evidence recorded (P2.7:
    a confidence follows the status a person sets). Held by a failure it carries
    none; released by an invalidation it comes back with the control's -- never
    more. Before P2.7 the person's SUPPORTED carried none, and the release came
    back with 0.28 above it: confidence the evidence put there."""
    _, control = _person_supported("conf-control")
    assert control.confidence == strength_from_evidence_class(control.evidence_class)

    _, claim = _person_supported("conf-held")
    fail = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED and claim.confidence is None
    ea.invalidate_claim_evidence(fail, actor=_user("releaser"), reason="probe hit staging")
    claim.refresh_from_db()
    assert claim.status == control.status == Status.SUPPORTED
    assert claim.confidence == control.confidence

    # And a derived VERIFIED keeps its own confidence through a hold and release.
    verified = _access_claim(_deployment("conf-verified"))
    before = verified.confidence
    against = _record(verified, outcome=V.FAIL.value)
    assert verified.confidence is None
    ea.invalidate_claim_evidence(against, actor=_user("releaser2"), reason="probe hit staging")
    verified.refresh_from_db()
    assert verified.status == Status.VERIFIED and verified.confidence == before


# ---------------------------------------------------------------------------
# 2. A successor that asserts nothing retires nothing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "successor",
    [
        pytest.param(
            dict(outcome=V.INSUFFICIENT_EVIDENCE.value, evidence_class=EvidenceClass.UNKNOWN.value,
                 state_check_ref="", state_checked_at=None, signer="", signature_verified=False, content_digest=""),
            id="insufficient-evidence-ungraded-unchecked-unsigned",
        ),
        pytest.param(dict(outcome=V.INSUFFICIENT_EVIDENCE.value), id="insufficient-evidence"),
        pytest.param(dict(outcome=V.INCOMPLETE.value), id="incomplete"),
        pytest.param(dict(evidence_class=EvidenceClass.UNKNOWN.value), id="pass-ungraded"),
        pytest.param(dict(state_check_ref="", state_checked_at=None), id="pass-unchecked"),
    ],
)
def test_a_successor_that_asserts_nothing_never_retires_a_contradiction(successor):
    """S2. A successor reading insufficient_evidence -- ungraded, unchecked, unsigned,
    recorded by nobody -- retired a load-bearing FAIL: VERIFIED went back to pass,
    0.88, with no invalidation and no attribution. Only a successor that meets the
    bar a PASS must meet (independent, live, on this subject, checked, graded) can
    retire what it supersedes."""
    claim = _access_claim(_deployment())
    fail = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.UNKNOWN and claim.evidence_verdict == V.CONTESTED

    ea.record_claim_evidence(claim, supersedes=fail, **_good(claim, **successor))
    claim.refresh_from_db()

    assert _admitted(claim, fail), "an item that asserts nothing retired a load-bearing failure"
    assert claim.status == Status.UNKNOWN and claim.confidence is None
    assert claim.evidence_verdict == V.CONTESTED
    entry = _supersession(claim, fail)
    assert entry is not None and entry["retired"] is False and entry["why"]


def test_a_person_supported_contradiction_is_not_retired_by_a_successor_that_asserts_nothing():
    _, claim = _person_supported("person")
    fail = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED
    ea.record_claim_evidence(
        claim, supersedes=fail,
        **_good(claim, outcome=V.INSUFFICIENT_EVIDENCE.value, evidence_class=EvidenceClass.UNKNOWN.value,
                state_check_ref="", state_checked_at=None),
    )
    claim.refresh_from_db()
    assert claim.status == Status.CONTRADICTED and claim.evidence_verdict == V.FAIL


# ---------------------------------------------------------------------------
# 3. A successor retires only what it observed after
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("gap", [timedelta(days=80), timedelta(0)], ids=["eighty-days-earlier", "same-instant"])
def test_an_observation_no_later_than_a_contradiction_never_retires_it(gap):
    """S3. A PASS observed 80 days before the FAIL it superseded (inside the TTL)
    retired it: VERIFIED, pass, 0.88. What was seen earlier says nothing about what
    was seen after it; a successor retires only what it observed strictly later."""
    claim = _access_claim(_deployment())
    now = timezone.now()
    seen = now - timedelta(minutes=1)
    fail = _record(claim, outcome=V.FAIL.value, observed_at=seen)
    assert claim.status == Status.UNKNOWN

    earlier = seen - gap
    ea.record_claim_evidence(
        claim, supersedes=fail, **_good(claim, observed_at=earlier, state_checked_at=earlier)
    )
    claim.refresh_from_db()

    assert _admitted(claim, fail)
    assert claim.status == Status.UNKNOWN and claim.evidence_verdict == V.CONTESTED
    entry = _supersession(claim, fail)
    assert entry is not None
    assert (entry["retired"], entry["why"]) == (False, "successor_not_observed_later")


def test_a_later_checked_observation_still_retires_what_it_supersedes():
    """The minimal pair: observed after, and carrying weight -- it retires the
    failure, and the audit records that it did."""
    claim = _access_claim(_deployment())
    now = timezone.now()
    fail = _record(claim, outcome=V.FAIL.value, observed_at=now - timedelta(minutes=5))
    ea.record_claim_evidence(
        claim, supersedes=fail, **_good(claim, observed_at=now - timedelta(minutes=2))
    )
    claim.refresh_from_db()
    assert ea.SUPERSEDED in _refused(claim, fail)
    assert claim.status == Status.VERIFIED
    assert _supersession(claim, fail)["retired"] is True


# ---------------------------------------------------------------------------
# 4. A contradiction is a stop
# ---------------------------------------------------------------------------


def _with_evidence(n: int, name: str):
    dep = _deployment(name)
    claim = _access_claim(dep)
    now = timezone.now()
    base = _good(claim)
    ClaimEvidence.objects.bulk_create(
        ClaimEvidence(
            deployment=dep, claim_fingerprint=claim.fingerprint, recorded_against=claim,
            subject_deployment=base["subject_deployment"], subject_claim_type=claim.claim_type,
            subject_route=base["subject_route"], subject_inputs=base["subject_inputs"],
            origin=Origin.INDEPENDENT, outcome=V.PASS.value,
            evidence_class=EvidenceClass.TECHNICALLY_VERIFIED.value, observed_at=now,
            state_check_ref="x", state_checked_at=now, expires_at=now + timedelta(days=30),
        )
        for _ in range(n)
    )
    return claim


def _contradict(claim, admin):
    with CaptureQueriesContext(connection) as queries:
        started = time.perf_counter()
        apply_claim_transition(claim, Status.CONTRADICTED, actor=admin, note="take it down")
        took = time.perf_counter() - started
    return took, [q["sql"] for q in queries.captured_queries]


def test_a_contradiction_does_no_evidence_work_before_it_is_written():
    """S6. A contradiction read every item recorded against the claim, the route
    serving now, and classified them all -- twice -- before its write: 4 ms with no
    evidence, 50 ms with 300, over 400 ms with 3,000. A stop's cost does not grow
    with anything recorded beside it."""
    empty, loaded = _with_evidence(0, "empty"), _with_evidence(3000, "loaded")
    admin = _user("stopper")

    t_empty, q_empty = _contradict(empty, admin)
    t_loaded, q_loaded = _contradict(loaded, admin)

    for sql in q_empty + q_loaded:
        assert ClaimEvidence._meta.db_table not in sql, f"a contradiction read the evidence: {sql[:200]}"
    assert len(q_loaded) == len(q_empty)
    assert t_loaded < t_empty + 0.1, f"contradiction took {t_loaded:.3f}s with 3,000 items, {t_empty:.3f}s with none"
    for claim in (empty, loaded):
        claim.refresh_from_db()
        assert claim.status == Status.CONTRADICTED


def test_an_evidence_audit_that_raises_cannot_refuse_or_undo_a_contradiction(monkeypatch):
    claim = _access_claim(_deployment())
    _record(claim)  # evidence on record, so every audit path has something to read
    other = _access_claim(_deployment("over-http"))
    _record(other)
    client = APIClient()
    client.force_authenticate(user=_user("http-stopper"))
    stopper = _user("stopper")

    def broken(*args, **kwargs):
        raise RuntimeError("the evidence audit is broken")

    for name in ("audit_of", "refusal_for_transition", "evidence_for", "audit", "classify", "audit_claim"):
        monkeypatch.setattr(ea, name, broken)
    monkeypatch.setattr("assurance.served_route.serving_route_now", broken)

    apply_claim_transition(claim, Status.CONTRADICTED, actor=stopper, note="take it down")
    assert AssuranceClaim.objects.get(pk=claim.pk).status == Status.CONTRADICTED

    response = client.post(
        f"/api/assurance/claims/{other.uuid}/transition/", {"to_status": "contradicted"}, format="json"
    )
    assert response.status_code == 200, response.content
    assert AssuranceClaim.objects.get(pk=other.pk).status == Status.CONTRADICTED


def test_the_audit_a_contradiction_skipped_is_brought_current_by_the_next_one():
    """Nothing is lost by the stop not auditing: the next audit of the claim -- a
    re-derive here -- reads the person's CONTRADICTED as the reading, and the
    passing evidence against it as a contest. It does not lift it."""
    claim = _with_evidence(3, "later")
    apply_claim_transition(claim, Status.CONTRADICTED, actor=_user("stopper"), note="take it down")
    derive_claims(claim.deployment)
    after = _current(claim.deployment)
    assert after.pk == claim.pk and after.status == Status.CONTRADICTED
    assert after.evidence_verdict == V.CONTESTED


# ---------------------------------------------------------------------------
# 5. The state check is judged on the digest, not on its spelling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "check",
    ["sha256:7f3a9c", "SHA256:7F3A9C", "7f3a9c", "7F3A9C", " Sha256:7f3A9c ", "ATHENA-SCAN-KEY-1"],
)
def test_a_state_check_that_is_the_record_in_another_spelling_is_not_a_state_check(check):
    """S4. ``SHA256:7F3A9C`` and a bare ``7f3a9c`` were admitted as an independent
    check of a record whose digest is ``sha256:7f3a9c``; the upper-cased one retired
    a FAIL. Both sides are compared stripped, lower-cased and without an algorithm
    prefix -- the signer too."""
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, state_check_ref=check)
    assert ea.STATE_CHECK_IS_THE_RECORD in (_refused(claim, item) or [])

    dep = _deployment("chain")
    verified = _access_claim(dep)
    fail = _record(verified, outcome=V.FAIL.value)
    ea.record_claim_evidence(verified, supersedes=fail, **_good(verified, state_check_ref=check))
    verified.refresh_from_db()
    assert _admitted(verified, fail) and verified.status == Status.UNKNOWN


def test_a_state_check_that_merely_resembles_the_digest_still_counts():
    """The minimal pair: a real check reference that is not the digest is admitted."""
    claim = _access_claim(_deployment(), principals=False)
    item = _record(claim, state_check_ref="achilles:probe/7f3a9c-run")
    assert _admitted(claim, item)


# ---------------------------------------------------------------------------
# 6. What a load-bearing failure does, written down both ways
# ---------------------------------------------------------------------------


def test_a_load_bearing_failure_contradicts_a_reading_without_its_own_observation_and_contests_one_with():
    """S5. The rule, as it is: a load-bearing FAIL against a claim whose own reading
    is an observed pass (VERIFIED on configuration-verified evidence) is a contest
    -- UNKNOWN, no confidence -- because the claim's reading is pass-side evidence
    too; against a reading with no observation of its own it is CONTRADICTED. Both
    hold the claim back; neither lifts it."""
    observed = _access_claim(_deployment("observed"))
    assert observed.status == Status.VERIFIED
    _record(observed, outcome=V.FAIL.value)
    assert observed.evidence_verdict == V.CONTESTED
    assert observed.status == Status.UNKNOWN and observed.confidence is None
    assert "the claim's own reading" in observed.evidence_audit["contradictions"][0]

    unobserved = _access_claim(_deployment("unobserved"), principals=False)
    assert unobserved.status == Status.UNKNOWN
    _record(unobserved, outcome=V.FAIL.value)
    assert unobserved.evidence_verdict == V.FAIL
    assert unobserved.status == Status.CONTRADICTED and unobserved.confidence is None

    # A person's SUPPORTED over an unobserved reading is not an observation either.
    _, person = _person_supported("person-fail")
    _record(person, outcome=V.FAIL.value)
    assert person.evidence_verdict == V.FAIL and person.status == Status.CONTRADICTED


# ---------------------------------------------------------------------------
# 7. Attribution of an invalidation
# ---------------------------------------------------------------------------


def test_an_invalidations_attribution_survives_deleting_the_account():
    claim = _access_claim(_deployment())
    fail = _record(claim, outcome=V.FAIL.value)
    reviewer = _user("departing-reviewer")
    ea.invalidate_claim_evidence(fail, actor=reviewer, reason="probe hit staging")
    reviewer.delete()

    stored = ClaimEvidence.objects.get(pk=fail.pk)
    event = ea.evidence_record(stored)["claim"]["invalidation_events"][0]
    assert event["by"] == "departing-reviewer"
    # Still retired: the attribution is on the record, not on the account.
    ea.audit_claim(_current(claim.deployment))
    claim.refresh_from_db()
    assert ea.INVALIDATED in _refused(claim, fail) and claim.status == Status.VERIFIED


def test_an_invalidation_nobody_is_attributed_with_retires_nothing():
    """classify read only ``invalidated_at``: a row stamped invalidated by anything
    but :func:`invalidate_claim_evidence` -- a bulk update, a restore -- released the
    hold with nobody attributed."""
    claim = _access_claim(_deployment())
    fail = _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.UNKNOWN
    ClaimEvidence.objects.filter(pk=fail.pk).update(invalidated_at=timezone.now(), invalidation_reason="bulk")

    ea.audit_claim(claim)
    claim.refresh_from_db()
    assert _admitted(claim, fail)
    assert claim.status == Status.UNKNOWN and claim.evidence_verdict == V.CONTESTED
    assert any(str(fail.uuid) in line and "attributed" in line for line in claim.evidence_audit["residual_uncertainty"])


# ---------------------------------------------------------------------------
# 8. #343: an assertion's evidence class is capped by its source
# ---------------------------------------------------------------------------

_BOUNDARY_FIELDS = (("region", "eu-west-1"), ("trains_on_data", "No"), ("subprocessors", "none"))


def _boundary_claim(source, label=EvidenceClass.CONFIGURATION_VERIFIED):
    dep = Deployment.objects.create(name=f"b-{source or 'blank'}", owner=_user(f"owner-b-{source or 'blank'}"))
    provider = Provider.objects.create(name=f"EU Model Co {source or 'blank'}", kind=Provider.Kind.MODEL_PROVIDER)
    for field, value in _BOUNDARY_FIELDS:
        ProviderAssertion.objects.create(provider=provider, field=field, value=value, evidence_class=label, source=source)
    Asset.objects.create(
        deployment=dep, provider=provider, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt",
        classification=Asset.Classification.APPROVED,
    )
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu"], training_allowed=False, third_party_sharing_allowed=False
    )
    derive_claims(dep)
    return _current(dep, ClaimType.DATA_BOUNDARY)


Source = ProviderAssertion.Source


@pytest.mark.parametrize(
    "source, status, evidence_class, vendor_asserted",
    [
        # Only an independent measurement observes the configuration.
        (Source.MEASURED, Status.VERIFIED, EvidenceClass.CONFIGURATION_VERIFIED, False),
        # A contract proves what the vendor contracted to, not what is configured.
        (Source.CONTRACT, Status.SUPPORTED, EvidenceClass.CONTRACTUALLY_STATED, False),
        # A document on file supports the fact; it does not observe it.
        (Source.VENDOR_DOC, Status.SUPPORTED, EvidenceClass.DOCUMENT_SUPPORTED, False),
        # The vendor's word, however it is labelled.
        (Source.SELF_DECLARED, Status.SUPPORTED, EvidenceClass.VENDOR_ASSERTED, True),
        # No source recorded is no better than the vendor's word.
        ("", Status.SUPPORTED, EvidenceClass.VENDOR_ASSERTED, True),
    ],
)
def test_a_boundary_claim_takes_no_stronger_evidence_than_the_assertions_source_proves(
    source, status, evidence_class, vendor_asserted
):
    """#343 (S8). Three assertions labelled configuration_verified with the default
    self_declared source promoted DATA_BOUNDARY to VERIFIED, vendor_asserted False,
    0.88: a vendor's word, relabelled, verified the claim."""
    claim = _boundary_claim(source)
    assert claim.status == status
    assert claim.evidence_class == evidence_class
    assert claim.vendor_asserted is vendor_asserted
    assert (claim.verified_at is not None) is (status == Status.VERIFIED)


@pytest.mark.parametrize(
    "source, evidence_class, vendor_asserted",
    [
        (Source.MEASURED, EvidenceClass.CONFIGURATION_VERIFIED, False),
        (Source.SELF_DECLARED, EvidenceClass.VENDOR_ASSERTED, True),
    ],
)
def test_the_ai_bom_claim_takes_no_stronger_evidence_than_the_assertions_source_proves(
    source, evidence_class, vendor_asserted
):
    """The same labels read by the AI-BOM deriver: it never verifies, but a
    self-declared configuration_verified label gave it vendor_asserted False and
    0.88 confidence -- the vendor's word, graded as an observation."""
    claim = _boundary_claim(source)
    bom = _current(claim.deployment, ClaimType.AI_BOM)
    assert bom.evidence_class == evidence_class
    assert bom.vendor_asserted is vendor_asserted
    # The strength mythos-core's class table gives the capped class, and no other.
    assert bom.confidence == strength_from_evidence_class(evidence_class)


def test_a_weaker_label_is_never_raised_by_a_strong_source():
    claim = _boundary_claim(Source.MEASURED, label=EvidenceClass.VENDOR_ASSERTED)
    assert claim.status == Status.SUPPORTED and claim.vendor_asserted is True


def test_every_assertion_source_has_a_written_ceiling():
    assert set(ProviderAssertion.SOURCE_CEILING) == set(Source.values) | {""}
    for source, ceiling in ProviderAssertion.SOURCE_CEILING.items():
        verified = ceiling in (EvidenceClass.TECHNICALLY_VERIFIED, EvidenceClass.CONFIGURATION_VERIFIED)
        assert verified is (source == Source.MEASURED), source


def test_a_self_declared_configuration_verified_label_over_the_api_is_kept_but_never_verifies():
    """The route keeps accepting the label (it is what the vendor said), shows the
    class it actually carries, and the claim derived from it is not verified."""
    admin = _user("api-admin")
    client = APIClient()
    client.force_authenticate(user=admin)
    dep = Deployment.objects.create(name="api", owner=admin)
    provider = Provider.objects.create(name="EU Model Co api", kind=Provider.Kind.MODEL_PROVIDER)
    for field, value in _BOUNDARY_FIELDS:
        response = client.post(
            "/api/assurance/provider-assertions/",
            {"provider": str(provider.uuid), "field": field, "value": value,
             "evidence_class": "configuration_verified", "source": "self_declared"},
            format="json",
        )
        assert response.status_code == 201, response.content
    Asset.objects.create(
        deployment=dep, provider=provider, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt",
        classification=Asset.Classification.APPROVED,
    )
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu"], training_allowed=False, third_party_sharing_allowed=False
    )
    assert client.post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/", {}, format="json").status_code == 200
    claim = _current(dep, ClaimType.DATA_BOUNDARY)
    assert claim.status == Status.SUPPORTED and claim.vendor_asserted is True and claim.verified_at is None
    assert response.json()["evidence_class"] == "configuration_verified"
    assert response.json()["effective_evidence_class"] == "vendor_asserted"


# ---------------------------------------------------------------------------
# 9. The evidence read is bounded; a near-miss subject is never silent
# ---------------------------------------------------------------------------


def test_the_evidence_read_is_bounded_and_says_so():
    claim = _with_evidence(260, "many")
    client = APIClient()
    client.force_authenticate(user=_user("reader"))
    url = f"/api/assurance/claims/{claim.uuid}/evidence/"

    body = client.get(url).json()
    assert len(body["evidence"]) < 260
    assert body["evidence_count"] == 260
    assert body["returned"] == len(body["evidence"]) == body["page_size"]
    assert body["truncated"] is True

    seen = {e["uuid"] for e in body["evidence"]}
    offset = body["returned"]
    while offset < 260:
        page = client.get(url, {"offset": offset}).json()
        assert page["evidence_count"] == 260
        seen |= {e["uuid"] for e in page["evidence"]}
        offset += page["returned"]
        assert page["returned"] > 0
    assert len(seen) == 260
    assert client.get(url, {"offset": "-1"}).status_code == 400
    assert client.get(url, {"offset": "x"}).status_code == 400


@pytest.mark.parametrize(
    "field, value",
    [
        ("subject_deployment", lambda c: str(c.deployment.uuid).upper()),
        ("subject_claim_type", lambda c: f" {c.claim_type} "),
        ("subject_claim_type", lambda c: c.claim_type.upper()),
    ],
)
def test_a_subject_that_differs_only_in_case_or_spacing_weighs_nothing_and_says_so(field, value):
    """Subjects bind exactly -- nothing here normalises what an item names -- but
    an adverse item that missed this claim only by case or spacing used to weigh
    nothing silently. It still weighs nothing; the audit now says why."""
    claim = _access_claim(_deployment())
    item = _record(claim, outcome=V.FAIL.value, **{field: value(claim)})
    reasons = _refused(claim, item)
    assert "subject_mismatch" in reasons
    assert claim.status == Status.VERIFIED  # not normalised into binding
    assert any(str(item.uuid) in line and "case or spacing" in line
               for line in claim.evidence_audit["residual_uncertainty"])
