"""The human review a signed Financial Exposure Receipt needs (section 28 hardening,
T9a; ``docs/economics/spec-v1.md``, section 35.4), for the tests that sign one.

A receipt is refused (``scenario_not_reviewed``) unless the latest review of the
run's scenario version is approved by a person who authored no version of it and
recorded none of the parameter-set versions it rests on (review round 1 of #169, M3),
and whose role was not granted by an author (anywhere up the chain, M2), by
themselves, or after the version was recorded. The tests that sign receipts record that review here, as a client records
it through ``POST .../scenarios/<uuid>/reviews/``: the gate stays ON, as it is by
default, and every receipt they sign has passed it.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db.models import Q

from accounts.models import RoleGrant
from assurance.economics.engine import governance
from assurance.economics.models import FinancialScenario, ScenarioReview, input_authors


def _scenario_of(scenario) -> FinancialScenario:
    if isinstance(scenario, FinancialScenario):
        return scenario
    return FinancialScenario.objects.get(pk=scenario.scenario_id)


def colleague_of(scenario):
    """The first admin or analyst account (by id) that authored no version of
    ``scenario``, recorded none of the parameter-set versions it rests on, and held its
    role before the version was recorded: the colleague a route's review would come
    from. Fails the test if the fixtures made none."""
    version = _scenario_of(scenario)
    authors = FinancialScenario.authors_of(version.pk) + input_authors(version.pk)
    for account in get_user_model().objects.filter(
        Q(role__in=("admin", "analyst")) | Q(is_superuser=True), is_active=True
    ).order_by("pk"):
        person = governance.Person(id=account.pk, username=account.get_username())
        grant = RoleGrant.latest_for(account.pk)
        held_before = grant is None or grant.granted_at < version.recorded_at
        if held_before and not any(governance.same_person(author, person) for author in authors):
            return account
    raise AssertionError("the fixtures hold no admin or analyst who could review this scenario version")


def approve_for_receipt(scenario, reviewer=None) -> ScenarioReview:
    """Record the approval a receipt of ``scenario`` (a scenario version, or a
    simulation result of one) needs, by ``reviewer``: an account that authored no
    version of it and held its role before the version was recorded
    (:func:`colleague_of` when not given)."""
    version = _scenario_of(scenario)
    reviewer = reviewer or colleague_of(version)
    return ScenarioReview.objects.create(scenario=version, reviewer=reviewer, verdict="approved")
