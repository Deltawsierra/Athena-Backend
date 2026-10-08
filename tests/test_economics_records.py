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

Review round 1 added a section per finding, each named for it. Phase E1 adds the
FX and cost-index observations at the end: the committed SYNTHETIC TEST DATA
snapshot registered as a source (licence ``open``, trust ``unverified``), its
observations stored exactly and read back into the same normalization, and every
refusal the engine gives held on the row too.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, models, transaction

from assurance.economics import snapshots
from assurance.economics.engine.cost_index import IndexSelector
from assurance.economics.engine.fx import FXPolicy
from assurance.economics.engine.money import Money
from assurance.economics.engine.normalization import NormalizationPolicy, normalize
from assurance.economics.models import (
    CostIndexObservation,
    EconomicsRefused,
    EconomicsRewriteRefused,
    FinancialScenario,
    FinancialSource,
    FXObservation,
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


def _fx(source, **over):
    fields = {
        "source": source,
        "base_currency": "EUR",
        "quote_currency": "USD",
        "rate": Decimal("1.0850"),
        "rate_type": "reference",
        "provider": "SYNTHETIC-REF",
        "observed_at": RETRIEVED,
        "effective_date": date(2026, 10, 1),
        "source_snapshot_hash": source.snapshot_hash,
    }
    fields.update(over)
    return FXObservation.objects.create(**fields)


def _index(source, **over):
    fields = {
        "source": source,
        "series_id": "SYN-CPI-US",
        "geography": "US",
        "category": "consumer prices, all items (SYNTHETIC)",
        "base": "2020-03=100",
        "period": "2026-09",
        "value": Decimal("124.500"),
        "vintage_date": date(2026, 10, 1),
    }
    fields.update(over)
    return CostIndexObservation.objects.create(**fields)


def _every_record(deployment, people):
    scenario = _scenario(deployment, people["alice"])
    override = SensitiveOverride.objects.create(
        scenario=scenario, subject="revenue_per_hour", reason="customer-confirmed", requested_by=people["alice"]
    )
    source = _source()
    return [
        source,
        _fx(source),
        _index(source),
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
        unreviewed.check_usable_for_production(None)
    assert refused.value.code == "unreviewed_license"
    reviewed = _source(license_class="open", trust_tier="authoritative")
    reviewed.check_usable_for_production(None)
    assert list(FinancialSource.objects.usable_for_production(None)) == [reviewed]


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


# ===================================================================== review round 1


# --- M1: the reviewer authored no version of the scenario -------------------


def test_m1_an_author_cannot_review_through_a_machine_drafted_superseding_version(deployment, people):
    """The reviewer's P1: alice's v1, superseded by a v2 nobody authored. Alice
    approving v2 approved her own work."""
    v1 = _scenario(deployment, people["alice"], title="v1")
    v2 = _scenario(deployment, None, title="v1 again", supersedes=v1)
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        ScenarioReview.objects.create(scenario=v2, reviewer=people["alice"], verdict="approved")
    assert refused.value.code == "author_reviews_own_scenario"
    assert ScenarioReview.objects.create(scenario=v2, reviewer=people["bob"], verdict="approved").pk


def test_m1_an_author_cannot_review_through_a_colleagues_superseding_version(deployment, people):
    """The reviewer's P1b: alice's v1, superseded by bob's v2, and again by carol's v3."""
    v1 = _scenario(deployment, people["alice"], title="v1")
    v2 = _scenario(deployment, people["bob"], title="v2", supersedes=v1)
    v3 = _scenario(deployment, people["carol"], title="v3", supersedes=v2)
    for author in ("alice", "bob", "carol"):
        with pytest.raises(SeparationOfDutiesRefused) as refused:
            ScenarioReview.objects.create(scenario=v3, reviewer=people[author], verdict="approved")
        assert refused.value.code == "author_reviews_own_scenario", author
    dave = User.objects.create_user(username="dave", password="x")
    assert ScenarioReview.objects.create(scenario=v3, reviewer=dave, verdict="approved").pk
    # The earlier version is reviewed against its own line only.
    assert ScenarioReview.objects.create(scenario=v1, reviewer=people["bob"], verdict="returned").pk


def test_m1_a_line_no_person_authored_is_not_reviewable(deployment, people):
    v1 = _scenario(deployment, None, title="drafted")
    v2 = _scenario(deployment, None, title="redrafted", supersedes=v1)
    for version in (v1, v2):
        with pytest.raises(SeparationOfDutiesRefused) as refused:
            ScenarioReview.objects.create(scenario=version, reviewer=people["bob"], verdict="approved")
        assert refused.value.code == "author_not_named"


def test_m1_the_authors_are_read_from_the_rows_not_the_object_passed(deployment, people):
    v1 = _scenario(deployment, people["alice"], title="v1")
    v2 = _scenario(deployment, people["bob"], title="v2", supersedes=v1)
    # An in-memory version told it has no author and supersedes nothing.
    v2.author, v2.author_username, v2.supersedes = None, "", None
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        ScenarioReview.objects.create(scenario=v2, reviewer=people["alice"], verdict="approved")
    assert refused.value.code == "author_reviews_own_scenario"


# --- M2: a review, request or approval needs an account -----------------------


def test_m2_an_override_is_never_in_force_on_approvals_that_name_no_account(deployment, people):
    """The reviewer's P2 and P2b: typed-in names stood for approvers."""
    override = SensitiveOverride.objects.create(
        scenario=_scenario(deployment, people["carol"]), subject="x", reason="y", requested_by=people["alice"]
    )
    for name in ("ghost-1", "bob-other-hat"):
        with pytest.raises(SeparationOfDutiesRefused) as refused:
            OverrideApproval.objects.create(override=override, approver=None, approver_username=name)
        assert refused.value.code == "approver_not_named"
    OverrideApproval.objects.create(override=override, approver=people["bob"])
    assert override.approval_refusal() == "override_needs_two_approvers"
    assert override.approvals.count() == 1


def test_m2_the_username_is_always_the_accounts_own(deployment, people):
    scenario = FinancialScenario.objects.create(
        deployment=deployment, title="s", author=people["alice"], author_username="someone-else"
    )
    assert FinancialScenario.objects.get(pk=scenario.pk).author_username == "alice"
    override = SensitiveOverride.objects.create(
        scenario=scenario, subject="x", reason="y", requested_by=people["bob"], requested_by_username="alice"
    )
    approval = OverrideApproval.objects.create(override=override, approver=people["carol"], approver_username="bob")
    review = ScenarioReview.objects.create(
        scenario=scenario, reviewer=people["carol"], reviewer_username="bob", verdict="approved"
    )
    source = _source(recorded_by=people["bob"], recorded_by_username="alice")
    stored = (
        SensitiveOverride.objects.get(pk=override.pk).requested_by_username,
        OverrideApproval.objects.get(pk=approval.pk).approver_username,
        ScenarioReview.objects.get(pk=review.pk).reviewer_username,
        FinancialSource.objects.get(pk=source.pk).recorded_by_username,
    )
    assert stored == ("bob", "carol", "carol", "bob")


def test_m2_no_account_no_name(deployment, people):
    """A typed-in name with no account is never written: a scenario's author name
    is blank without an author, and a review or request without one is refused."""
    machine = FinancialScenario.objects.create(deployment=deployment, title="s", author=None, author_username="alice")
    assert FinancialScenario.objects.get(pk=machine.pk).author_username == ""
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        ScenarioReview.objects.create(scenario=machine, reviewer=None, reviewer_username="bob", verdict="approved")
    assert refused.value.code == "reviewer_not_named"
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        SensitiveOverride.objects.create(
            scenario=machine, subject="x", reason="y", requested_by=None, requested_by_username="alice"
        )
    assert refused.value.code == "requester_not_named"


def test_m2_a_removed_accounts_name_still_counts_when_read(deployment, people):
    """The one place a username stands without its account: a row read after the
    account was removed. The approval still counts, and still bars that person."""
    override = SensitiveOverride.objects.create(
        scenario=_scenario(deployment, people["carol"]), subject="x", reason="y", requested_by=people["alice"]
    )
    OverrideApproval.objects.create(override=override, approver=people["bob"])
    people["bob"].delete()
    assert [p.username for p in override.approvers()] == ["bob"]
    returning = User.objects.create_user(username="bob", password="x")
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        OverrideApproval.objects.create(override=override, approver=returning)
    assert refused.value.code == "approver_already_approved"
    OverrideApproval.objects.create(override=override, approver=people["carol"])
    assert override.in_force


def test_m2_in_force_is_read_from_the_rows_not_the_object(deployment, people):
    override = SensitiveOverride.objects.create(
        scenario=_scenario(deployment, people["carol"]), subject="x", reason="y", requested_by=people["alice"]
    )
    OverrideApproval.objects.create(override=override, approver=people["bob"])
    # An in-memory override told someone else asked for it: alice is still the
    # requester, so she still may not approve, and carol still may.
    override.requested_by, override.requested_by_username = people["carol"], "carol"
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        OverrideApproval.objects.create(override=override, approver=people["alice"])
    assert refused.value.code == "requester_approves_own_override"
    OverrideApproval.objects.create(override=override, approver=people["carol"])
    # Told bob asked for it, it is still in force: bob and carol approved alice's request.
    override.requested_by, override.requested_by_username = people["bob"], "bob"
    assert override.in_force
    override.check_in_force()


# --- L1: nothing may intercept the base manager the stop's writes use ---------


def test_l1_the_base_manager_stays_djangos_plain_one():
    """Removing an operator and the deployment cascade write through the base
    manager; setting ``Meta.base_manager_name`` to the append-only manager would
    refuse them (spec, sections 2 and 10)."""
    for model in (
        FinancialSource, ModelInventoryEntry, FinancialScenario, ScenarioReview, SensitiveOverride, OverrideApproval,
        FXObservation, CostIndexObservation,
    ):
        assert model._meta.base_manager_name is None, model
        assert type(model._base_manager) is models.Manager, model
        assert not isinstance(model._base_manager.all(), type(model.objects.all())), model


# --- L2: codes and required text --------------------------------------------


def test_l2_a_coded_field_holds_one_of_its_codes(deployment, people):
    """The reviewer's P4."""
    scenario = _scenario(deployment, people["alice"])
    for verdict in ("", "rubber-stamp"):
        with pytest.raises(EconomicsRefused) as refused:
            ScenarioReview.objects.create(scenario=scenario, reviewer=people["bob"], verdict=verdict)
        assert (refused.value.code, refused.value.detail) == ("code_unrecognised", "verdict")
    for field in ("license_class", "trust_tier"):
        with pytest.raises(EconomicsRefused) as refused:
            _source(**{field: "bogus"})
        assert (refused.value.code, refused.value.detail) == ("code_unrecognised", field)


def test_l2_required_text_is_never_blank(deployment, people):
    for field in ("source_key", "provider", "dataset", "schema_version"):
        with pytest.raises(EconomicsRefused) as refused:
            _source(**{field: " "})
        assert (refused.value.code, refused.value.detail) == ("required_field_blank", field)
    with pytest.raises(EconomicsRefused) as refused:
        _scenario(deployment, people["alice"], title="")
    assert (refused.value.code, refused.value.detail) == ("required_field_blank", "title")
    assert not FinancialSource.objects.exists() and not FinancialScenario.objects.exists()


def test_l2_the_database_refuses_a_code_written_past_save(deployment, people):
    """The check constraints hold where save is bypassed."""
    review = ScenarioReview(
        scenario=_scenario(deployment, people["alice"]), reviewer=people["bob"], verdict="rubber-stamp"
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(review, force_insert=True)
    for field in ("license_class", "trust_tier"):
        row = FinancialSource(
            source_key=f"k-{field}", version=1, provider="p", dataset="d", retrieved_at=RETRIEVED,
            snapshot_hash=SNAPSHOT, schema_version="1", **{field: "bogus"},
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            models.Model.save(row, force_insert=True)


# --- L3: production use is per tenant ----------------------------------------


def test_l3_a_run_uses_the_platform_sources_and_its_own_deployments_only(deployment):
    """The reviewer's P5: every tenant's sources were usable by any run."""
    other = Deployment.objects.create(name="other-tenant")
    platform = _source(license_class="open")
    mine = _source(deployment=deployment, license_class="customer", trust_tier="customer", source_key="revenue")
    theirs = _source(deployment=other, license_class="customer", source_key="revenue")
    _source(deployment=deployment, source_key="unreviewed-feed")
    assert set(FinancialSource.objects.usable_for_production(deployment)) == {platform, mine}
    assert set(FinancialSource.objects.usable_for_production(other)) == {platform, theirs}
    assert set(FinancialSource.objects.usable_for_production(None)) == {platform}
    mine.check_usable_for_production(deployment)
    platform.check_usable_for_production(other)
    with pytest.raises(SourceNotUsableForProduction) as refused:
        theirs.check_usable_for_production(deployment)
    assert refused.value.code == "cross_tenant_reference"


def test_l3_a_platform_wide_source_is_never_customer_data(deployment):
    for field in ("license_class", "trust_tier"):
        with pytest.raises(EconomicsRefused) as refused:
            _source(**{field: "customer"})
        assert refused.value.code == "customer_source_without_tenant"
        row = FinancialSource(
            source_key=f"k-{field}", version=1, provider="p", dataset="d", retrieved_at=RETRIEVED,
            snapshot_hash=SNAPSHOT, schema_version="1", **{field: "customer"},
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            models.Model.save(row, force_insert=True)
    assert _source(deployment=deployment, license_class="customer", trust_tier="customer").pk


# --- L5: the stop's writes are never held back --------------------------------


def test_removing_an_operator_is_never_held_back_by_economics_rows(deployment, people):
    """Removing an operator is a stop (``accounts:user-detail`` DELETE). With the
    operator named in every economics role, it answers 204 through the real route,
    nulls the account columns, keeps the names, and the override approved by them
    stays in force."""
    from rest_framework.test import APIClient

    admin = User.objects.create_user(username="rv-admin", password="x", role="admin")
    leaver = User.objects.create_user(username="leaver", password="x", role="analyst")
    _source(recorded_by=leaver)
    ModelInventoryEntry.objects.create(
        model_id="m", version="1", owner="o", intended_use="u", limitations="l", recorded_by=leaver
    )
    mine = _scenario(deployment, leaver, title="theirs to write")
    theirs = _scenario(deployment, people["alice"], title="someone else's")
    ScenarioReview.objects.create(scenario=theirs, reviewer=leaver, verdict="approved")
    asked = SensitiveOverride.objects.create(scenario=mine, subject="x", reason="y", requested_by=leaver)
    approved = SensitiveOverride.objects.create(scenario=theirs, subject="x", reason="y", requested_by=people["bob"])
    OverrideApproval.objects.create(override=asked, approver=people["alice"])
    OverrideApproval.objects.create(override=asked, approver=people["bob"])
    OverrideApproval.objects.create(override=approved, approver=leaver)
    OverrideApproval.objects.create(override=approved, approver=people["carol"])

    client = APIClient()
    client.force_authenticate(user=admin)
    response = client.delete(f"/api/accounts/users/{leaver.pk}/")
    assert response.status_code == 204, response.content
    assert not User.objects.filter(pk=leaver.pk).exists()

    assert list(FinancialSource.objects.values_list("recorded_by_id", "recorded_by_username")) == [(None, "leaver")]
    assert list(ModelInventoryEntry.objects.values_list("recorded_by_id", flat=True)) == [None]
    assert FinancialScenario.objects.get(pk=mine.pk).author_username == "leaver"
    assert ScenarioReview.objects.get().reviewer_id is None
    assert asked.in_force and approved.in_force


# ===================================================== phase E1: observations

#: The committed snapshot's hash (tests/test_economics_money.py pins it too).
SYNTHETIC_HASH = "sha256:e719dc303cf8eb9e2c72bc80d0261ddf4fdac810d59ebcb5472f09075c48b90f"
US_CPI = IndexSelector("SYN-CPI-US", "US", "consumer prices, all items (SYNTHETIC)", "2020-03=100", "USD")


def test_the_synthetic_snapshot_is_registered_open_and_unverified():
    source = snapshots.register_snapshot()
    assert (source.source_key, source.version, source.deployment_id) == ("synthetic-fx-and-cost-index", 1, None)
    assert (source.license_class, source.trust_tier) == ("open", "unverified")
    assert source.snapshot_hash == SYNTHETIC_HASH
    assert source.dataset.startswith("SYNTHETIC TEST DATA")
    assert source.fx_observations.count() == 18 and source.cost_index_observations.count() == 7
    assert set(source.fx_observations.values_list("source_snapshot_hash", flat=True)) == {SYNTHETIC_HASH}
    # Registering the same bytes again writes nothing.
    assert snapshots.register_snapshot().pk == source.pk
    assert FinancialSource.objects.count() == 1 and FXObservation.objects.count() == 18


def test_stored_observations_read_back_exactly_and_normalize_the_same():
    """Django keeps a decimal on SQLite as a float rounded to 15 digits; every
    column holds 15 at most, so what is read back is what was written, and the
    normalization from the rows equals the one from the file."""
    snap = snapshots.read_snapshot()
    source = snapshots.register_snapshot()
    stored = {(r.provider, r.rate_type, r.base, r.quote, r.effective_date): r.rate for r in
              (row.as_engine() for row in FXObservation.objects.filter(source=source))}
    assert stored == {(r.provider, r.rate_type, r.base, r.quote, r.effective_date): r.rate for r in snap.fx_rates}
    assert all(type(v) is Decimal for v in stored.values())
    assert sorted(CostIndexObservation.objects.values_list("value", flat=True)) == sorted(
        p.value for p in snap.index_points
    )
    policy = NormalizationPolicy("USD", "EUR", FXPolicy(("SYNTHETIC-REF",)), US_CPI)
    args = {"event_date": date(2020, 3, 2), "valuation_date": date(2026, 9, 30), "policy": policy}
    from_file = normalize(Money.parse("1000.00", "EUR"), fx_book=snap.fx_book(), index_book=snap.index_book(), **args)
    from_rows = normalize(
        Money.parse("1000.00", "EUR"),
        fx_book=snapshots.fx_book([source], snap.holidays),
        index_book=snapshots.index_book([source]),
        **args,
    )
    assert from_rows.value == from_file.value and from_rows.display() == "1309.52 EUR"
    rows_chain, file_chain = from_rows.as_dict()["chain"], from_file.as_dict()["chain"]
    # The rows name their source version; otherwise the chains are the same.
    for step in rows_chain:
        for observation in step["observations"]:
            assert observation.pop("source_version") == 1
    for step in file_chain:
        for observation in step["observations"]:
            assert observation.pop("source_version") is None
    assert rows_chain == file_chain


@pytest.mark.parametrize(
    "over, code",
    [
        ({"rate": 1.085}, "not_decimal"),
        ({"rate": "1.085"}, "not_decimal"),
        ({"rate": Decimal("NaN")}, "not_finite"),
        ({"rate": Decimal("0")}, "rate_not_positive"),
        ({"rate": Decimal("-1.085")}, "rate_not_positive"),
        ({"rate": Decimal("1.0850000001")}, "value_precision"),
        ({"rate": Decimal("1234567.123456789")}, "value_precision"),
        ({"quote_currency": "EUR"}, "pair_malformed"),
        ({"quote_currency": "XAU"}, "currency_retired"),
        ({"base_currency": "eur"}, "currency_unknown"),
        ({"rate_type": "spot"}, "rate_type_unrecognised"),
        ({"provider": " "}, "required_field_blank"),
        ({"observed_at": datetime(2026, 10, 1, 9)}, "date_malformed"),
        ({"source_snapshot_hash": "sha256:" + "00" * 32}, "snapshot_hash_mismatch"),
        ({"source_snapshot_hash": "00" * 32}, "snapshot_hash_malformed"),
    ],
)
def test_an_fx_observation_the_engine_refuses_is_refused(over, code):
    source = _source()
    with pytest.raises(EconomicsRefused) as refused:
        _fx(source, **over)
    assert refused.value.code == code
    assert not FXObservation.objects.exists()


@pytest.mark.parametrize(
    "over, code",
    [
        ({"value": 124.5}, "not_decimal"),
        ({"value": Decimal("Infinity")}, "not_finite"),
        ({"value": Decimal("0")}, "index_value_not_positive"),
        ({"value": Decimal("124.5000001")}, "value_precision"),
        ({"period": "2026-9"}, "period_malformed"),
        ({"vintage_date": date(2026, 8, 31)}, "date_inversion"),
        # Review round 1, L2: inside its own month, before the month ended.
        ({"vintage_date": date(2026, 9, 15)}, "date_inversion"),
        ({"vintage_date": date(2026, 9, 29)}, "date_inversion"),
        ({"series_id": ""}, "required_field_blank"),
    ],
)
def test_a_cost_index_observation_the_engine_refuses_is_refused(over, code):
    source = _source()
    with pytest.raises(EconomicsRefused) as refused:
        _index(source, **over)
    assert refused.value.code == code
    assert not CostIndexObservation.objects.exists()


def test_a_series_stays_one_geography_and_category_in_a_source():
    source = _source()
    _index(source)
    with pytest.raises(EconomicsRefused) as refused:
        _index(source, period="2026-10", vintage_date=date(2026, 11, 13), geography="EA")
    assert refused.value.code == "index_series_mismatch"
    with pytest.raises(IntegrityError), transaction.atomic():
        _index(source, value=Decimal("124.600"))  # same series, period and vintage


def test_the_database_refuses_a_bad_rate_written_past_save():
    source = _source()
    for over in ({"rate": Decimal("0")}, {"rate_type": "spot"}, {"quote_currency": "EUR"}):
        row = FXObservation(
            **{
                "source": source, "base_currency": "EUR", "quote_currency": "USD", "rate": Decimal("1.1"),
                "rate_type": "reference", "provider": "p", "observed_at": RETRIEVED,
                "effective_date": date(2026, 10, 1), "source_snapshot_hash": source.snapshot_hash, **over,
            }
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            models.Model.save(row, force_insert=True)
    index = CostIndexObservation(
        source=source, series_id="s", geography="US", category="c", period="2026-09", value=Decimal("-1"),
        vintage_date=date(2026, 10, 1),
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(index, force_insert=True)


def test_a_tenants_snapshot_goes_with_its_deployment(deployment):
    snapshots.register_snapshot(deployment=deployment)
    platform = snapshots.register_snapshot()
    assert FinancialSource.objects.count() == 2 and FXObservation.objects.count() == 36
    deployment.delete()
    assert list(FinancialSource.objects.all()) == [platform]
    assert FXObservation.objects.count() == 18 and CostIndexObservation.objects.count() == 7
    assert set(FXObservation.objects.values_list("source_id", flat=True)) == {platform.pk}


def test_removing_an_operator_who_registered_a_snapshot_is_never_held_back(people):
    """The observations name no account; the source the operator recorded keeps
    their name, and the stop answers 204."""
    from rest_framework.test import APIClient

    admin = User.objects.create_user(username="rv-admin", password="x", role="admin")
    leaver = User.objects.create_user(username="leaver", password="x", role="analyst")
    source = snapshots.register_snapshot(recorded_by=leaver)
    client = APIClient()
    client.force_authenticate(user=admin)
    response = client.delete(f"/api/accounts/users/{leaver.pk}/")
    assert response.status_code == 204, response.content
    stored = FinancialSource.objects.get(pk=source.pk)
    assert (stored.recorded_by_id, stored.recorded_by_username) == (None, "leaver")
    assert stored.fx_observations.count() == 18


# ===================================================================== review round 1 (E1)


def test_r1_m1_the_synthetic_snapshot_is_never_usable_for_production(deployment):
    """Review round 1, M1: the fixture is licensed ``open``, a reviewed class, so the
    licence-only gate returned made-up rates to a production run. A synthetic source
    is refused whatever its licence."""
    source = snapshots.register_snapshot()
    assert source not in FinancialSource.objects.usable_for_production(None)
    assert source not in FinancialSource.objects.usable_for_production(deployment)
    assert source.synthetic is True and FinancialSource.objects.get(pk=source.pk).synthetic is True
    assert source.production_use_refusal(None) == "synthetic_source"
    with pytest.raises(SourceNotUsableForProduction) as refused:
        source.check_usable_for_production(None)
    assert refused.value.code == "synthetic_source"
    # A real, reviewed source beside it still is usable.
    real = _source(source_key="fed-h10", license_class="open", trust_tier="authoritative")
    assert list(FinancialSource.objects.usable_for_production(None)) == [real]
    assert real.synthetic is False


def test_r1_m1_a_synthetic_source_is_never_trusted_above_unverified():
    with pytest.raises(EconomicsRefused) as refused:
        _source(synthetic=True, license_class="open", trust_tier="authoritative")
    assert (refused.value.code, refused.value.detail) == ("synthetic_source", "trust_tier")
    assert not FinancialSource.objects.exists()
    row = FinancialSource(
        source_key="written-past-save", version=1, provider="p", dataset="d", retrieved_at=RETRIEVED,
        snapshot_hash=SNAPSHOT, schema_version="1", synthetic=True, trust_tier="benchmark",
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(row, force_insert=True)
    assert _source(synthetic=True).trust_tier == "unverified"


def test_r1_m3_a_series_stays_on_one_base_in_a_source():
    """Review round 1, M3: a stored series rebased within one source is refused,
    so no book read from the rows can divide one base by another."""
    source = _source()
    _index(source)
    with pytest.raises(EconomicsRefused) as refused:
        _index(source, period="2026-10", vintage_date=date(2026, 11, 13), base="2026=100", value=Decimal("98.4"))
    assert refused.value.code == "index_series_mismatch"
    with pytest.raises(EconomicsRefused) as refused:
        _index(source, period="2026-10", vintage_date=date(2026, 11, 13), base="")
    assert refused.value.code == "required_field_blank"
    assert CostIndexObservation.objects.count() == 1

