"""Phase 2 item 5a — the bitemporal claim model.

The roadmap's need, in its own words:

> ``AssuranceClaim`` has only single-temporal ``valid_from``/``valid_to`` — no
> split between *when something was true* (effective time) and *when Mythos
> learned it* (recorded time), so a late-arriving observation about an earlier
> state can't be represented without corrupting the claim's own history.

And the bar: *a claim about a state that held yesterday but was only observed
today is recorded without silently overwriting today's already-current claim.*

The model had TWO date columns and a comment calling them "Bitemporal validity",
and a class docstring saying "history is bitemporal". Both were wrong in the same
way: ``valid_from``/``valid_to`` are set at derivation and closed at supersession,
so they track when Mythos *believed* a version and say nothing about when the
described state held. One axis wearing the name of two.

The fix turns on what **current** means. It is no longer "believed now" but
"believed now AND effective now", so a claim learned today about a window that
closed yesterday is believed, is findable, and is not current — which is what lets
it be recorded at all, because the partial unique constraint only admits one
current row per claim identity.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from assurance.claims import record_retroactive_claim
from assurance.models import AssuranceClaim, Deployment

pytestmark = pytest.mark.django_db

User = get_user_model()


def _deployment(name="checkout-assistant"):
    owner = User.objects.create_user(
        username=f"u-{Deployment.objects.count()}",
        password="x",
        role=User.Roles.ANALYST,
    )
    return Deployment.objects.create(name=name, owner=owner)


def _claim(
    dep,
    *,
    fingerprint="fp-1",
    effective_from=None,
    effective_to=None,
    valid_to=None,
    **kw,
):
    now = timezone.now()
    return AssuranceClaim.objects.create(
        deployment=dep,
        claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY,
        statement="destinations are inside the approved boundary",
        fingerprint=fingerprint,
        system_fingerprint="sysfp",
        policy_version="pol",
        environment=dep.environment,
        status=AssuranceClaim.ClaimStatus.SUPPORTED,
        valid_from=kw.pop("valid_from", now),
        valid_to=valid_to,
        effective_from=effective_from or now,
        effective_to=effective_to,
        **kw,
    )


# ---------------------------------------------------------------------------
# The two axes are distinct
# ---------------------------------------------------------------------------


def test_an_ordinary_claim_is_effective_from_when_it_was_recorded():
    """The honest default for a derive: we observed it now and have no evidence
    about earlier, so the effective window opens now and stays open."""
    dep = _deployment()
    claim = _claim(dep)
    assert claim.effective_from is not None
    assert claim.effective_to is None
    assert claim.valid_to is None


def test_the_recorded_and_effective_windows_can_differ():
    """The whole point of there being two. A claim recorded today about last week
    carries today on one axis and last week on the other."""
    dep = _deployment()
    now = timezone.now()
    claim = _claim(
        dep,
        valid_from=now,
        effective_from=now - timedelta(days=8),
        effective_to=now - timedelta(days=1),
    )
    assert claim.valid_from > claim.effective_from
    assert claim.effective_to < claim.valid_from


# ---------------------------------------------------------------------------
# What "current" means
# ---------------------------------------------------------------------------


def test_current_means_believed_now_and_effective_now():
    dep = _deployment()
    live = _claim(dep, fingerprint="a")
    superseded = _claim(dep, fingerprint="b", valid_to=timezone.now())
    retroactive = _claim(dep, fingerprint="c", effective_to=timezone.now())

    current = set(AssuranceClaim.objects.filter(deployment=dep).current())
    assert current == {live}
    assert superseded not in current, (
        "a version Mythos no longer believes is not current"
    )
    assert retroactive not in current, "a claim about a closed window is not current"


def test_believed_now_includes_the_retroactive_claim_and_current_does_not():
    """Two different questions, and conflating them is how a decision gets computed
    from a fact about last week. Naming them apart is the fix."""
    dep = _deployment()
    live = _claim(dep, fingerprint="a")
    retroactive = _claim(dep, fingerprint="c", effective_to=timezone.now())

    assert set(AssuranceClaim.objects.filter(deployment=dep).believed_now()) == {
        live,
        retroactive,
    }
    assert set(AssuranceClaim.objects.filter(deployment=dep).current()) == {live}


def test_effective_at_finds_what_held_then_whenever_we_learned_it():
    dep = _deployment()
    now = timezone.now()
    week_ago = now - timedelta(days=7)
    past = _claim(
        dep,
        fingerprint="a",
        effective_from=week_ago - timedelta(days=1),
        effective_to=week_ago + timedelta(days=1),
    )
    live = _claim(dep, fingerprint="b", effective_from=now - timedelta(hours=1))

    assert set(
        AssuranceClaim.objects.filter(deployment=dep).effective_at(week_ago)
    ) == {past}
    assert set(AssuranceClaim.objects.filter(deployment=dep).effective_at(now)) == {
        live
    }


def test_an_open_effective_window_contains_every_later_moment():
    dep = _deployment()
    now = timezone.now()
    live = _claim(dep, effective_from=now - timedelta(days=3))
    at = AssuranceClaim.objects.filter(deployment=dep).effective_at(
        now + timedelta(days=99)
    )
    assert set(at) == {live}


# ---------------------------------------------------------------------------
# The constraint, and the collision it used to force
# ---------------------------------------------------------------------------


def test_two_current_versions_of_one_claim_identity_are_still_refused():
    dep = _deployment()
    _claim(dep, fingerprint="same")
    with pytest.raises(IntegrityError), transaction.atomic():
        _claim(dep, fingerprint="same")


def test_a_retroactive_claim_sits_beside_the_current_one_without_colliding():
    """The bar. Under one axis this insert had to either overwrite today's claim or
    be dropped — the row would have collided on `uq_current_claim` because it is
    still believed. Closing its effective window is what makes room."""
    dep = _deployment()
    now = timezone.now()
    today = _claim(dep, fingerprint="same")

    yesterday = _claim(
        dep,
        fingerprint="same",
        effective_from=now - timedelta(days=2),
        effective_to=now - timedelta(days=1),
    )

    today.refresh_from_db()
    assert today.valid_to is None and today.effective_to is None, (
        "today's claim was untouched"
    )
    assert set(AssuranceClaim.objects.filter(deployment=dep).current()) == {today}
    assert yesterday in AssuranceClaim.objects.filter(deployment=dep).believed_now()


def test_two_retroactive_claims_about_different_windows_both_persist():
    """History is append-only on the effective axis too: learning about two past
    windows is two facts, not one overwriting the other."""
    dep = _deployment()
    now = timezone.now()
    _claim(dep, fingerprint="same")
    one = _claim(
        dep,
        fingerprint="same",
        effective_from=now - timedelta(days=4),
        effective_to=now - timedelta(days=3),
    )
    two = _claim(
        dep,
        fingerprint="same",
        effective_from=now - timedelta(days=2),
        effective_to=now - timedelta(days=1),
    )
    assert one.pk != two.pk
    assert (
        AssuranceClaim.objects.filter(deployment=dep, fingerprint="same").count() == 3
    )


# ---------------------------------------------------------------------------
# record_retroactive_claim
# ---------------------------------------------------------------------------


def test_recording_a_late_observation_does_not_disturb_the_current_claim():
    dep = _deployment()
    now = timezone.now()
    today = _claim(dep, fingerprint="untouched")
    before = (today.status, today.valid_to, today.effective_to, today.updated_at)

    late = record_retroactive_claim(
        dep,
        claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY,
        statement="a destination outside the boundary was in use",
        effective_from=now - timedelta(days=3),
        effective_to=now - timedelta(days=2),
        system_fingerprint="old-sysfp",
        status=AssuranceClaim.ClaimStatus.CONTRADICTED,
        evidence_class=AssuranceClaim._meta.get_field("evidence_class").choices[0][0],
    )

    today.refresh_from_db()
    assert (
        today.status,
        today.valid_to,
        today.effective_to,
        today.updated_at,
    ) == before
    assert late.valid_to is None, "Mythos believes it"
    assert late.effective_to is not None, "about a window that has closed"
    assert late not in AssuranceClaim.objects.filter(deployment=dep).current()


def test_a_retroactive_claim_records_both_dates_in_its_lifecycle_event():
    """The event says when we learned it and what period it is about — the two
    facts an auditor needs to tell a late observation from a stale one."""
    dep = _deployment()
    now = timezone.now()
    late = record_retroactive_claim(
        dep,
        claim_type=AssuranceClaim.ClaimType.AI_BOM,
        statement="an undeclared component was present",
        effective_from=now - timedelta(days=3),
        effective_to=now - timedelta(days=2),
        system_fingerprint="old",
        status=AssuranceClaim.ClaimStatus.CONTRADICTED,
        evidence_class=AssuranceClaim._meta.get_field("evidence_class").choices[0][0],
    )
    note = late.events.first().note
    assert "Recorded" in note
    assert (now - timedelta(days=3)).isoformat() in note


def test_an_open_effective_window_is_refused_rather_than_recorded():
    """A retroactive claim with an open effective window is a claim about NOW, and
    belongs in derive_claims where it contends for the current slot properly.
    Accepting it here would put a second live row in the constraint's blind spot."""
    dep = _deployment()
    with pytest.raises(ValueError, match="must close its effective window"):
        record_retroactive_claim(
            dep,
            claim_type=AssuranceClaim.ClaimType.AI_BOM,
            statement="x",
            effective_from=timezone.now() - timedelta(days=1),
            effective_to=None,
            system_fingerprint="s",
            status=AssuranceClaim.ClaimStatus.SUPPORTED,
            evidence_class=AssuranceClaim._meta.get_field("evidence_class").choices[0][
                0
            ],
        )


def test_an_inverted_effective_window_is_refused():
    dep = _deployment()
    now = timezone.now()
    with pytest.raises(ValueError, match="after effective_from"):
        record_retroactive_claim(
            dep,
            claim_type=AssuranceClaim.ClaimType.AI_BOM,
            statement="x",
            effective_from=now,
            effective_to=now - timedelta(days=1),
            system_fingerprint="s",
            status=AssuranceClaim.ClaimStatus.SUPPORTED,
            evidence_class=AssuranceClaim._meta.get_field("evidence_class").choices[0][
                0
            ],
        )


# ---------------------------------------------------------------------------
# Nothing hand-rolls "current" any more
# ---------------------------------------------------------------------------


def test_no_module_spells_the_currency_filter_by_hand():
    """The guard that makes the rest of this file mean something.

    Nine call sites used to write ``valid_to__isnull=True`` to mean current. That
    was right with one axis and is a silent defect with two: such a filter returns
    retroactive claims as live, a decision is computed from a fact about last week,
    and nothing fails — the query runs and returns rows.

    So the definition lives on the queryset and this enumerates the codebase rather
    than spot-checking the sites that happened to be remembered. `models.py` is
    exempt: it is where the definition is written.
    """
    root = Path(__file__).resolve().parent.parent / "assurance"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "models.py" or "migrations" in path.parts:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if "valid_to__isnull" in line:
                offenders.append(f"{path.relative_to(root)}:{number}")
    assert offenders == [], (
        "these hand-roll the currency filter instead of using .current()/"
        f".believed_now(): {offenders}"
    )


def test_the_constraint_itself_carries_both_temporal_halves():
    """Found by a surviving mutation: dropping the effective half from the model's
    constraint broke no test here, because the test database is built from the
    MIGRATION and the model's `Meta` is not what the database enforces.

    `makemigrations --check` does catch the drift and CI runs it — but a guard that
    lives only in a different job is a guard this suite cannot see, and the next
    person to widen the constraint will be reading this file. So the condition is
    asserted directly.
    """
    constraint = next(
        c for c in AssuranceClaim._meta.constraints if c.name == "uq_current_claim"
    )
    condition = str(constraint.condition)
    assert "valid_to__isnull" in condition, "the recorded half is missing"
    assert "effective_to__isnull" in condition, (
        "the effective half is missing: a retroactive claim would collide with "
        "today's claim and could not be recorded at all"
    )


def test_the_model_no_longer_claims_a_bitemporality_it_lacks():
    """The docstring said "history is bitemporal" while the schema had one axis.
    A comment that overstates a property is the same defect as a control that does
    not enforce one: a reader trusts it and stops looking."""
    from assurance import models as models_module

    doc = models_module.AssuranceClaim.__doc__
    assert "append-only and never rewritten" in doc
    assert "recorded" in doc and "effective" in doc
