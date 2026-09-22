"""Phase 2 item 6 — legal staleness as a second axis, and the human materiality gate.

The roadmap's need: ``invalidation.py`` tracks only *system-state* drift. It has
no notion of **legal** staleness — a jurisdiction's rule changing while the
deployment is unchanged — and no gate distinguishing "the system changed" from
"the system changed in a way that is legally material".

And the sentence the whole design answers to:

> Treating every config edit as automatically legally material (or automatically
> not) is dishonest in both directions.

An automatic *yes* floods a review queue until nobody reads it. An automatic *no*
means the axis never fires and the record quietly claims a legal currency nobody
checked. So the trigger flags and never judges, and only a person with a written
rationale can move the legal axis to current or stale.

The bar, in two parts, and both are tested here:

1. *a claim can be technically STALE and legally current, or technically current
   and legally STALE, and SPINE tracks both states distinctly* — all four
   combinations, each asserted;
2. *no legal-materiality judgment is ever auto-applied without a recorded human
   decision* — including the negative judgment, because "not material" is a
   finding too and a default that silently means "fine" is the thing this item
   exists to remove.
"""

from __future__ import annotations

from datetime import date

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from assurance.legal import (
    MaterialityDecisionRefused,
    flag_for_materiality_review,
    legal_posture,
    obligations_for,
    record_materiality_decision,
    supersede_obligation,
)
from assurance.models import (
    AssuranceClaim,
    Deployment,
    LegalObligation,
    LegalStatus,
    MaterialityDecision,
)

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus


def _user(name="counsel"):
    return User.objects.create_user(
        username=f"{name}-{User.objects.count()}", password="x", role=User.Roles.ANALYST
    )


def _deployment(name="checkout-assistant"):
    return Deployment.objects.create(name=name, owner=_user("owner"))


def _claim(dep, *, fingerprint="fp-1", status=Status.SUPPORTED, legal_status=None):
    # legal_status is passed ONLY when a test asks for one. Defaulting it here to
    # NOT_ASSESSED would have meant no test in this file ever read the field's real
    # default -- which is exactly the gap a mutation found: flipping the model
    # default to CURRENT broke nothing, because every claim overrode it.
    extra = {} if legal_status is None else {"legal_status": legal_status}
    return AssuranceClaim.objects.create(
        deployment=dep,
        claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY,
        statement="destinations are inside the approved boundary",
        fingerprint=fingerprint,
        system_fingerprint="sysfp",
        policy_version="pol",
        environment=dep.environment,
        status=status,
        **extra,
    )


def _obligation(
    *, deployments=(), version="1", jurisdiction="EU", operative=None, tier=None
):
    obligation = LegalObligation.objects.create(
        jurisdiction=jurisdiction,
        authority_tier=tier or LegalObligation.AuthorityTier.REGULATION,
        source="AI Act",
        source_version=version,
        operative_date=operative or date(2026, 8, 1),
    )
    for dep in deployments:
        obligation.deployments.add(dep)
    return obligation


# ---------------------------------------------------------------------------
# The registry is its own record
# ---------------------------------------------------------------------------


def test_an_obligation_records_the_operative_date_not_just_when_we_saw_it():
    """When the rule BITES is not when it was published and not when we recorded
    it. A claim assessed before publication and one assessed after publication but
    before commencement are in different positions."""
    obligation = _obligation(operative=date(2027, 2, 2))
    assert obligation.operative_date == date(2027, 2, 2)
    assert obligation.created_at.date() != obligation.operative_date


def test_the_authority_tier_distinguishes_a_statute_from_an_advisory_note():
    """Both 'changed'. Treating them as the same event is how a review queue fills
    with noise until nobody reads it."""
    statute = _obligation(version="s", tier=LegalObligation.AuthorityTier.STATUTE)
    advisory = _obligation(version="a", tier=LegalObligation.AuthorityTier.ADVISORY)
    assert statute.authority_tier != advisory.authority_tier


def test_one_source_version_is_recorded_once():
    _obligation(version="1")
    with pytest.raises(IntegrityError), transaction.atomic():
        _obligation(version="1")


def test_binding_is_explicit_and_never_inferred_from_a_region():
    """Inferring that an EU data boundary implies a given regulation is a legal
    judgment about scope, and this layer does not make those."""
    dep = _deployment()
    unbound = _obligation()
    assert obligations_for(dep) == []

    unbound.deployments.add(dep)
    assert obligations_for(dep) == [unbound]


# ---------------------------------------------------------------------------
# The trigger flags; it never judges
# ---------------------------------------------------------------------------


def test_an_obligation_moving_flags_for_review_and_does_not_make_anything_stale():
    """The crux. The trigger observed that something changed; it has not
    established that the change matters here, and those are different facts."""
    dep = _deployment()
    claim = _claim(dep)
    obligation = _obligation(deployments=[dep])

    out = flag_for_materiality_review(obligation)

    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.REVIEW_PENDING
    assert claim.legal_status != LegalStatus.STALE
    assert out["flagged_count"] == 1
    assert out["judged"] is False, "the trigger must not claim to have judged"


def test_the_flag_leaves_the_technical_status_alone():
    dep = _deployment()
    claim = _claim(dep, status=Status.VERIFIED)
    flag_for_materiality_review(_obligation(deployments=[dep]))

    claim.refresh_from_db()
    assert claim.status == Status.VERIFIED, "the legal axis moved the technical one"


def test_a_claim_already_judged_legally_stale_is_not_re_flagged():
    """Re-flagging would lose the human decision that put it there: a claim does
    not become less stale because a second obligation moved."""
    dep = _deployment()
    claim = _claim(dep, legal_status=LegalStatus.STALE)
    flag_for_materiality_review(_obligation(deployments=[dep], version="2"))

    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.STALE


def test_a_claim_already_awaiting_review_is_not_flagged_twice():
    dep = _deployment()
    claim = _claim(dep, legal_status=LegalStatus.REVIEW_PENDING)
    out = flag_for_materiality_review(_obligation(deployments=[dep], version="2"))

    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.REVIEW_PENDING
    assert out["flagged_count"] == 0


def test_a_superseded_claim_version_is_not_flagged():
    """History does not go into a review queue. A superseded claim version is what
    we believed then; flagging it would put rows in front of a reviewer for a
    claim nobody acts on any more, and the queue is only useful while everything
    in it is live."""
    dep = _deployment()
    live = _claim(dep, fingerprint="live")
    history = _claim(dep, fingerprint="history")
    history.valid_to = timezone.now()
    history.save(update_fields=["valid_to"])

    result = flag_for_materiality_review(_obligation(deployments=[dep]))

    history.refresh_from_db()
    live.refresh_from_db()
    assert history.legal_status == LegalStatus.NOT_ASSESSED
    assert live.legal_status == LegalStatus.REVIEW_PENDING
    assert result["flagged"] == [str(live.uuid)]


def test_a_claim_whose_effective_window_has_closed_is_not_flagged():
    """The other half of current (Phase 2.5): a claim still believed but
    describing a window that has closed is not live either, and the trigger reads
    both axes because .current() does."""
    dep = _deployment()
    live = _claim(dep, fingerprint="live")
    retired = _claim(dep, fingerprint="retired")
    retired.effective_to = timezone.now()
    retired.save(update_fields=["effective_to"])

    result = flag_for_materiality_review(_obligation(deployments=[dep]))

    retired.refresh_from_db()
    assert retired.legal_status == LegalStatus.NOT_ASSESSED
    assert result["flagged"] == [str(live.uuid)]


def test_an_obligation_bound_to_nobody_flags_nothing():
    dep = _deployment()
    _claim(dep)
    out = flag_for_materiality_review(_obligation())
    assert out["flagged_count"] == 0


def test_the_flag_records_on_the_claims_lifecycle_that_nothing_was_judged():
    dep = _deployment()
    claim = _claim(dep)
    flag_for_materiality_review(_obligation(deployments=[dep]))

    note = claim.events.first().note
    assert "No materiality judgment has been made" in note
    assert "AI Act" in note


# ---------------------------------------------------------------------------
# Superseding a rule is what moves it
# ---------------------------------------------------------------------------


def test_superseding_links_the_versions_and_flags_for_review():
    """The trigger has a caller. A version chain nothing writes, and a flag
    function nothing reaches, would both be decoration."""
    dep = _deployment()
    claim = _claim(dep)
    v1 = _obligation(deployments=[dep], version="1")
    v2 = _obligation(version="2", operative=date(2027, 2, 1))

    result = supersede_obligation(v1, v2)

    v1.refresh_from_db()
    claim.refresh_from_db()
    assert v1.superseded_by_id == v2.pk
    assert list(v2.supersedes.all()) == [v1]
    assert claim.legal_status == LegalStatus.REVIEW_PENDING
    assert result["judged"] is False


def test_superseding_carries_the_bindings_forward():
    """A replacement that bound nothing would move every claim out of scope with
    nobody deciding to — the silent-zero shape, in legal clothing."""
    kept, also = _deployment("kept"), _deployment("also")
    _claim(kept), _claim(also)
    v1 = _obligation(deployments=[kept, also], version="1")
    v2 = _obligation(version="2", operative=date(2027, 2, 1))

    result = supersede_obligation(v1, v2)

    assert set(v2.deployments.values_list("pk", flat=True)) == {kept.pk, also.pk}
    assert sorted(result["bindings_carried_forward"]) == sorted(
        [str(kept.uuid), str(also.uuid)]
    )
    assert result["flagged_count"] == 2


def test_superseding_does_not_re_add_a_binding_the_replacement_already_had():
    dep = _deployment()
    v1 = _obligation(deployments=[dep], version="1")
    v2 = _obligation(deployments=[dep], version="2", operative=date(2027, 2, 1))

    result = supersede_obligation(v1, v2)

    assert result["bindings_carried_forward"] == []
    assert v2.deployments.count() == 1


def test_superseding_never_judges_materiality():
    """Even where the replacement is a statute and the old one advisory, nothing
    here decides that the change matters. That is the whole gate."""
    dep = _deployment()
    claim = _claim(dep, legal_status=LegalStatus.CURRENT)
    v1 = _obligation(
        deployments=[dep], version="1", tier=LegalObligation.AuthorityTier.ADVISORY
    )
    v2 = _obligation(
        version="2",
        operative=date(2027, 2, 1),
        tier=LegalObligation.AuthorityTier.STATUTE,
    )

    supersede_obligation(v1, v2)

    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.REVIEW_PENDING
    assert MaterialityDecision.objects.count() == 0


def test_an_obligation_cannot_supersede_itself():
    v1 = _obligation(version="1")
    with pytest.raises(ValueError):
        supersede_obligation(v1, v1)
    v1.refresh_from_db()
    assert v1.superseded_by_id is None


# ---------------------------------------------------------------------------
# The gate needs a person and a reason
# ---------------------------------------------------------------------------


def test_a_decision_without_a_decider_is_refused():
    """An unattributed legal judgment is not a human decision, and a row recorded
    without one would sit in the table looking exactly like a real judgment."""
    dep = _deployment()
    claim = _claim(dep)
    with pytest.raises(MaterialityDecisionRefused, match="the person who made it"):
        record_materiality_decision(
            claim,
            _obligation(deployments=[dep]),
            decided_by=None,
            material=True,
            rationale="because",
        )


def test_a_decision_without_a_rationale_is_refused():
    dep = _deployment()
    claim = _claim(dep)
    for empty in ("", "   ", "\n"):
        with pytest.raises(MaterialityDecisionRefused, match="written rationale"):
            record_materiality_decision(
                claim,
                _obligation(deployments=[dep], version=f"v{len(empty)}"),
                decided_by=_user(),
                material=True,
                rationale=empty,
            )


def test_a_refused_decision_records_nothing_and_moves_nothing():
    dep = _deployment()
    claim = _claim(dep, legal_status=LegalStatus.REVIEW_PENDING)
    with pytest.raises(MaterialityDecisionRefused):
        record_materiality_decision(
            claim,
            _obligation(deployments=[dep]),
            decided_by=_user(),
            material=True,
            rationale="",
        )
    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.REVIEW_PENDING
    assert MaterialityDecision.objects.count() == 0


def test_a_material_judgment_makes_the_claim_legally_stale():
    dep = _deployment()
    claim = _claim(dep, legal_status=LegalStatus.REVIEW_PENDING)
    reviewer = _user()

    decision = record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=reviewer,
        material=True,
        rationale="Article 14 now requires human oversight on this class of system.",
    )

    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.STALE
    assert decision.decided_by == reviewer
    assert decision.material is True


def test_a_not_material_judgment_is_a_finding_and_takes_a_decision_too():
    """ "Not material" is a positive conclusion someone reached, not a default. If
    it were free, the axis would read legally-current for every claim nobody ever
    looked at — which is the silent pass this item removes."""
    dep = _deployment()
    claim = _claim(dep, legal_status=LegalStatus.REVIEW_PENDING)

    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=_user(),
        material=False,
        rationale="The threshold in Annex III is not met by this deployment.",
    )

    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.CURRENT


def test_the_decision_is_attributed_on_the_claims_lifecycle_with_its_reasoning():
    dep = _deployment()
    claim = _claim(dep)
    reviewer = _user("gc")

    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=reviewer,
        material=True,
        rationale="Annex III class change.",
    )

    event = claim.events.first()
    assert event.actor == reviewer
    assert "Annex III class change." in event.note
    assert "material" in event.note


def test_the_decision_leaves_the_technical_status_untouched():
    dep = _deployment()
    claim = _claim(dep, status=Status.VERIFIED)
    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=_user(),
        material=True,
        rationale="r",
    )
    claim.refresh_from_db()
    assert claim.status == Status.VERIFIED


# ---------------------------------------------------------------------------
# The two axes are independent — all four combinations
# ---------------------------------------------------------------------------


def test_a_claim_can_be_technically_stale_and_legally_current():
    """The system moved; the law did not."""
    dep = _deployment()
    claim = _claim(dep, status=Status.STALE)
    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=_user(),
        material=False,
        rationale="unaffected",
    )
    claim.refresh_from_db()
    assert (claim.status, claim.legal_status) == (Status.STALE, LegalStatus.CURRENT)


def test_a_claim_can_be_technically_current_and_legally_stale():
    """The case the single axis could not express at all: the deployment sat still
    and the rule beneath it changed."""
    dep = _deployment()
    claim = _claim(dep, status=Status.VERIFIED)
    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=_user(),
        material=True,
        rationale="commencement",
    )
    claim.refresh_from_db()
    assert (claim.status, claim.legal_status) == (Status.VERIFIED, LegalStatus.STALE)


def test_a_claim_can_be_stale_on_both_axes_for_two_different_reasons():
    dep = _deployment()
    claim = _claim(dep, status=Status.STALE)
    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=_user(),
        material=True,
        rationale="both",
    )
    claim.refresh_from_db()
    assert (claim.status, claim.legal_status) == (Status.STALE, LegalStatus.STALE)


def test_a_claim_can_be_current_on_both():
    dep = _deployment()
    claim = _claim(dep, status=Status.VERIFIED)
    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=_user(),
        material=False,
        rationale="fine",
    )
    claim.refresh_from_db()
    assert (claim.status, claim.legal_status) == (Status.VERIFIED, LegalStatus.CURRENT)


def test_the_legal_axis_is_a_separate_field_and_not_a_status_value():
    """If legal staleness were another ClaimStatus value, the four combinations
    above would collapse into two the moment either one changed."""
    assert "legal_status" in {f.name for f in AssuranceClaim._meta.get_fields()}
    legal_field = AssuranceClaim._meta.get_field("legal_status")
    status_field = AssuranceClaim._meta.get_field("status")
    assert legal_field is not status_field


def test_no_legal_value_is_also_a_valid_claim_status_value():
    """Both enums want to say "stale", and both said it as the bare string once.

    That is not a naming nit. ``filter(status=LegalStatus.STALE)`` would have been
    a perfectly valid query returning the *technically* stale claims — the wrong
    rows, with no error anywhere. Disjoint raw values are what make the mistake
    loud instead of plausible.
    """
    legal_values = {value for value, _ in LegalStatus.choices}
    status_values = {value for value, _ in Status.choices}
    assert legal_values & status_values == set()


@pytest.mark.django_db
def test_a_legal_value_written_to_status_fails_validation():
    """The read half of the same mistake: a cross-wired write must not be storable."""
    claim = _claim(_deployment())
    claim.status = LegalStatus.STALE
    with pytest.raises(ValidationError):
        claim.full_clean()

    claim = _claim(_deployment())
    claim.legal_status = Status.STALE
    with pytest.raises(ValidationError):
        claim.full_clean()


# ---------------------------------------------------------------------------
# Not-assessed is not current
# ---------------------------------------------------------------------------


def test_a_new_claim_starts_not_assessed_and_not_legally_current():
    """A claim nobody has ever reviewed legally is not legally sound, it is
    unexamined. Reading the two as the same is how an unreviewed deployment ships
    looking compliant."""
    claim = _claim(_deployment())
    assert claim.legal_status == LegalStatus.NOT_ASSESSED
    assert claim.legal_status != LegalStatus.CURRENT
    # Read off the field too, so this cannot pass because some caller happened to
    # pass the right value.
    assert (
        AssuranceClaim._meta.get_field("legal_status").default
        == LegalStatus.NOT_ASSESSED
    )


def test_the_four_legal_states_are_distinct():
    assert (
        len(
            {
                LegalStatus.NOT_ASSESSED,
                LegalStatus.CURRENT,
                LegalStatus.REVIEW_PENDING,
                LegalStatus.STALE,
            }
        )
        == 4
    )


# ---------------------------------------------------------------------------
# The posture read
# ---------------------------------------------------------------------------


def test_the_posture_reports_the_three_gaps_separately_and_never_as_one_score():
    """Nine legally current and one never reviewed is not "90% compliant": it has
    an unexamined claim, and the number that hides it is the one a reader quotes."""
    dep = _deployment()
    reviewer = _user()
    obligation = _obligation(deployments=[dep])

    unassessed = _claim(dep, fingerprint="a")
    pending = _claim(dep, fingerprint="b", legal_status=LegalStatus.REVIEW_PENDING)
    stale = _claim(dep, fingerprint="c")
    record_materiality_decision(
        stale, obligation, decided_by=reviewer, material=True, rationale="r"
    )

    posture = legal_posture(dep)
    assert posture["never_legally_assessed"] == 1
    assert posture["awaiting_materiality_review"] == 1
    assert posture["legally_stale"] == 1
    assert posture["claim_count"] == 3
    assert "compliant" not in posture["summary"], "the summary must not imply a verdict"
    assert unassessed.legal_status == LegalStatus.NOT_ASSESSED
    assert pending.legal_status == LegalStatus.REVIEW_PENDING


def test_the_posture_counts_only_current_claim_versions():
    """A superseded claim's legal standing is history, and counting it would
    inflate whichever bucket it happens to sit in."""
    dep = _deployment()
    _claim(dep, fingerprint="a")
    superseded = _claim(dep, fingerprint="b")
    superseded.valid_to = timezone.now()
    superseded.save(update_fields=["valid_to"])

    assert legal_posture(dep)["claim_count"] == 1


def test_the_posture_names_the_obligations_it_was_read_against():
    dep = _deployment()
    obligation = _obligation(deployments=[dep])
    assert legal_posture(dep)["obligations"] == [str(obligation.uuid)]


# ---------------------------------------------------------------------------
# Nothing else may move the legal axis
# ---------------------------------------------------------------------------


def test_nothing_outside_the_gate_writes_the_legal_status():
    """The guard. A bare `claim.legal_status = STALE` anywhere would be a legal
    judgment made by code, with no person and no rationale behind it — exactly
    what the gate exists to prevent, and invisible because the field would look
    correctly set."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "assurance"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "legal.py" or "migrations" in path.parts:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if ".legal_status =" in line or "legal_status=LegalStatus.STALE" in line:
                offenders.append(f"{path.relative_to(root)}:{number}")
    assert offenders == [], (
        f"these set the legal axis outside assurance.legal: {offenders}"
    )


def test_a_second_decision_supersedes_the_first_and_both_are_kept():
    """Counsel can change their mind, and the earlier position must stay readable:
    a legal file that only shows the current view cannot show what was believed
    when an action was taken."""
    dep = _deployment()
    claim = _claim(dep)
    obligation = _obligation(deployments=[dep])
    reviewer = _user()

    record_materiality_decision(
        claim, obligation, decided_by=reviewer, material=False, rationale="first read"
    )
    record_materiality_decision(
        claim, obligation, decided_by=reviewer, material=True, rationale="on reflection"
    )

    claim.refresh_from_db()
    assert claim.legal_status == LegalStatus.STALE
    assert claim.materiality_decisions.count() == 2
    assert [d.material for d in claim.materiality_decisions.all()] == [True, False]


def test_the_decider_cannot_be_deleted_out_from_under_a_decision():
    """PROTECT, not SET_NULL: a decision whose decider was deleted is an
    unattributed legal judgment, and the record must not be able to become one."""
    from django.db.models import ProtectedError

    dep = _deployment()
    claim = _claim(dep)
    reviewer = _user()
    record_materiality_decision(
        claim,
        _obligation(deployments=[dep]),
        decided_by=reviewer,
        material=True,
        rationale="r",
    )
    with pytest.raises(ProtectedError):
        reviewer.delete()
