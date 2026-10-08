"""Economic Exposure's records (phase E0), against the database.

The models in :mod:`assurance.economics.models` exist before anything uses them,
and each enforces its rule on the row itself, so the first route that writes one
inherits the rule rather than re-implementing it:

- every record is append-only: a recorded row is never saved again or deleted,
  and its queryset refuses a bulk update, delete or create; a row goes only with
  its deployment;
- a source's versions count up, and an ``unreviewed`` source is never usable for a
  production run;
- a scenario's author never reviews it, even after the author's account is gone;
- a sensitive override is in force only with two different approvers, neither of
  them its requester;
- a scenario points into SPINE by SPINE's ids and never at another tenant's record.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, models, transaction

from assurance.economics.models import (
    EconomicsRefused,
    EconomicsRewriteRefused,
    FinancialScenario,
    FinancialSource,
    ModelInventoryEntry,
    OverrideApproval,
    ScenarioReview,
    SensitiveOverride,
    SeparationOfDutiesRefused,
    SourceNotUsableForProduction,
)
from assurance.models import Deployment

pytestmark = pytest.mark.django_db

User = get_user_model()
SNAPSHOT = "sha256:" + "5a" * 32
EFFECT = "sha256:" + "e1" * 32
RETRIEVED = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


@pytest.fixture
def people():
    return {name: User.objects.create_user(username=name, password="x") for name in ("alice", "bob", "carol")}


@pytest.fixture
def deployment():
    return Deployment.objects.create(name="payments-agent")


def _source(**over):
    fields = {
        "source_key": "fed-h10-daily",
        "provider": "Federal Reserve",
        "dataset": "H.10 foreign exchange rates",
        "url": "https://www.federalreserve.gov/releases/h10/",
        "retrieved_at": RETRIEVED,
        "snapshot_hash": SNAPSHOT,
        "schema_version": "1",
    }
    fields.update(over)
    return FinancialSource.objects.create(**fields)


def _scenario(deployment, author, **over):
    fields = {"deployment": deployment, "title": "Unauthorized payment by the agent", "author": author}
    fields.update(over)
    return FinancialScenario.objects.create(**fields)


# ------------------------------------------------------------- append-only


def _every_record(deployment, people):
    scenario = _scenario(deployment, people["alice"])
    override = SensitiveOverride.objects.create(
        scenario=scenario, subject="revenue_per_hour", reason="customer-confirmed", requested_by=people["alice"]
    )
    return [
        _source(),
        ModelInventoryEntry.objects.create(
            model_id="banking-payments", version="0.1.0", owner="model risk", intended_use="u", limitations="l"
        ),
        scenario,
        ScenarioReview.objects.create(scenario=scenario, reviewer=people["bob"], verdict="approved"),
        override,
        OverrideApproval.objects.create(override=override, approver=people["bob"]),
    ]


def test_a_recorded_row_is_never_saved_again_or_deleted(deployment, people):
    for row in _every_record(deployment, people):
        model = type(row)
        with pytest.raises(EconomicsRewriteRefused):
            row.save()
        with pytest.raises(EconomicsRewriteRefused):
            row.delete()
        # Re-read, edited, saved: still refused.
        again = model.objects.get(pk=row.pk)
        with pytest.raises(EconomicsRewriteRefused):
            again.save(update_fields=["uuid"])
        assert model.objects.filter(pk=row.pk).exists()


def test_the_queryset_refuses_every_bulk_write(deployment, people):
    for row in _every_record(deployment, people):
        model = type(row)
        rows = model.objects.filter(pk=row.pk)
        with pytest.raises(EconomicsRewriteRefused):
            rows.update(uuid=row.uuid)
        with pytest.raises(EconomicsRewriteRefused):
            rows.delete()
        with pytest.raises(EconomicsRewriteRefused):
            model.objects.bulk_update([row], ["uuid"])
        with pytest.raises(EconomicsRefused) as refused:
            model.objects.bulk_create([model()])
        assert refused.value.code == "bulk_create_refused"


def test_a_new_instance_carrying_a_recorded_key_does_not_overwrite_it():
    first = _source()
    imposter = FinancialSource(
        pk=first.pk,
        source_key="fed-h10-daily",
        version=99,
        provider="someone else",
        dataset="x",
        retrieved_at=RETRIEVED,
        snapshot_hash=SNAPSHOT,
        schema_version="1",
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        imposter.save()
    assert FinancialSource.objects.get(pk=first.pk).provider == "Federal Reserve"


def test_the_records_go_with_their_deployment(deployment, people):
    _every_record(deployment, people)
    _source(deployment=deployment, source_key="customer-revenue", license_class="customer")
    deployment.delete()
    for model in (FinancialScenario, ScenarioReview, SensitiveOverride, OverrideApproval):
        assert not model.objects.exists(), model
    # A platform-wide source and the inventory are no deployment's.
    assert list(FinancialSource.objects.values_list("source_key", flat=True)) == ["fed-h10-daily"]
    assert ModelInventoryEntry.objects.count() == 1


# ------------------------------------------------------------------ sources


def test_a_source_counts_its_versions_per_tenant(deployment):
    assert [_source().version, _source().version] == [1, 2]
    assert _source(deployment=deployment).version == 1
    with pytest.raises(IntegrityError), transaction.atomic():
        _source(version=2)


def test_an_unreviewed_source_is_never_usable_for_production():
    unreviewed = _source()
    assert unreviewed.license_class == "unreviewed"  # the default
    with pytest.raises(SourceNotUsableForProduction) as refused:
        unreviewed.check_usable_for_production()
    assert refused.value.code == "unreviewed_license"
    reviewed = _source(license_class="open", trust_tier="authoritative")
    reviewed.check_usable_for_production()
    assert list(FinancialSource.objects.usable_for_production()) == [reviewed]


def test_a_malformed_snapshot_hash_is_refused():
    with pytest.raises(EconomicsRefused) as refused:
        _source(snapshot_hash="5a" * 32)
    assert refused.value.code == "snapshot_hash_malformed"
    assert not FinancialSource.objects.exists()


def test_an_inventory_entry_says_what_the_model_is_for_and_counts_its_revisions():
    entry = {
        "model_id": "banking-payments",
        "version": "0.1.0",
        "owner": "model risk function",
        "intended_use": "decision support for the six banking scenario families",
        "limitations": "no legal fine prediction; no market-value loss in cash loss",
    }
    first = ModelInventoryEntry.objects.create(**entry)
    retired = ModelInventoryEntry.objects.create(**entry, retirement_date=date(2027, 6, 30))
    assert (first.revision, retired.revision) == (1, 2)
    with pytest.raises(EconomicsRefused) as refused:
        ModelInventoryEntry.objects.create(**{**entry, "limitations": ""})
    assert refused.value.code == "inventory_entry_incomplete"


# ---------------------------------------------------------- separation


def test_an_author_cannot_review_their_own_scenario(deployment, people):
    scenario = _scenario(deployment, people["alice"])
    assert scenario.author_username == "alice"
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        ScenarioReview.objects.create(scenario=scenario, reviewer=people["alice"], verdict="approved")
    assert refused.value.code == "author_reviews_own_scenario"
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        ScenarioReview.objects.create(scenario=scenario, reviewer=None, verdict="approved")
    assert refused.value.code == "reviewer_not_named"
    review = ScenarioReview.objects.create(scenario=scenario, reviewer=people["bob"], verdict="approved")
    assert review.reviewer_username == "bob"
    assert list(scenario.reviews.all()) == [review]


def test_the_author_is_still_the_author_after_their_account_is_gone(deployment, people):
    scenario = _scenario(deployment, people["alice"])
    people["alice"].delete()
    scenario = FinancialScenario.objects.get(pk=scenario.pk)
    assert (scenario.author_id, scenario.author_username) == (None, "alice")
    returning = User.objects.create_user(username="alice", password="x")
    with pytest.raises(SeparationOfDutiesRefused):
        ScenarioReview.objects.create(scenario=scenario, reviewer=returning, verdict="approved")


def test_a_sensitive_override_needs_two_distinct_approvers(deployment, people):
    scenario = _scenario(deployment, people["carol"])
    override = SensitiveOverride.objects.create(
        scenario=scenario, subject="revenue_per_hour", reason="customer-confirmed figure", requested_by=people["alice"]
    )
    assert not override.in_force
    OverrideApproval.objects.create(override=override, approver=people["bob"])
    assert override.approval_refusal() == "override_needs_two_approvers"
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        override.check_in_force()
    assert refused.value.code == "override_needs_two_approvers"

    with pytest.raises(SeparationOfDutiesRefused) as refused:
        OverrideApproval.objects.create(override=override, approver=people["bob"])
    assert refused.value.code == "approver_already_approved"
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        OverrideApproval.objects.create(override=override, approver=people["alice"])
    assert refused.value.code == "requester_approves_own_override"
    assert not override.in_force

    OverrideApproval.objects.create(override=override, approver=people["carol"])
    assert override.in_force
    override.check_in_force()


def test_one_person_cannot_approve_twice_even_racing_past_the_check(deployment, people):
    """The unique constraint is the backstop for two approvals written at once."""
    override = SensitiveOverride.objects.create(
        scenario=_scenario(deployment, people["carol"]), subject="x", reason="y", requested_by=people["alice"]
    )
    OverrideApproval.objects.create(override=override, approver=people["bob"])
    second = OverrideApproval(override=override, approver=people["bob"], approver_username="bob")
    with pytest.raises(IntegrityError), transaction.atomic():
        # What a write that read the approvals before the first one landed would do.
        models.Model.save(second, force_insert=True)
    assert override.approvals.count() == 1


def test_an_override_is_a_named_persons_request_with_a_reason(deployment, people):
    scenario = _scenario(deployment, people["carol"])
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        SensitiveOverride.objects.create(scenario=scenario, subject="x", reason="y", requested_by=None)
    assert refused.value.code == "requester_not_named"
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        SensitiveOverride.objects.create(scenario=scenario, subject="x", reason="", requested_by=people["alice"])
    assert refused.value.code == "override_incomplete"


# ----------------------------------------------------- references and tenants


def test_a_scenario_points_into_spine_by_spines_ids(deployment, people):
    scenario = _scenario(deployment, people["alice"], system_fingerprint="ab" * 32, causal_effect=EFFECT)
    assert scenario.causal_effect == EFFECT
    for field, value in (("causal_effect", "refund"), ("system_fingerprint", EFFECT)):
        with pytest.raises(EconomicsRefused) as refused:
            _scenario(deployment, people["alice"], **{field: value})
        assert refused.value.code == "spine_reference_malformed"


def test_a_scenario_never_supersedes_another_tenants(deployment, people):
    mine = _scenario(deployment, people["alice"])
    revised = _scenario(deployment, people["alice"], supersedes=mine)
    assert list(mine.superseded_by.all()) == [revised]
    other = Deployment.objects.create(name="someone-else")
    with pytest.raises(EconomicsRefused) as refused:
        _scenario(other, people["alice"], supersedes=mine)
    assert refused.value.code == "cross_tenant_reference"
