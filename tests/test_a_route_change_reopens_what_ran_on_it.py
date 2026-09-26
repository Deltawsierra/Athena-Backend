"""P2.2: a served-route change must retest the evidence gathered on that route.

The claims do not read the route -- the data boundary, the AI-BOM and effective
access are facts about the graph, and `test_a_served_route_fact_no_deriver_reads_moves_no_claim`
pins that a tokenizer change moves none of them. What a route change DOES reach is
the chain outcomes: each is an exercise of the system that served it. So each is
bound, when it is written, to the route the platform had noted as serving when it
was observed, and a `held` taken against any other route counts as not yet
exercised against this one.

These drive the real ingest and the real read path.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import outcome as oc

from assurance import composition as comp
from assurance import observed_outcomes
from assurance.composition import HELD, VIOLATED, ChainOutcome, compose
from assurance.decision import accepted_risk_signal, refresh_stored_decisions
from assurance.invalidation import check_invalidations
from assurance.models import (
    ApprovedWorkflow,
    Asset,
    Deployment,
    Finding,
    ServedRouteNote,
    WorkflowChainOutcome,
)
from assurance.revalidation import plan_revalidation
from assurance.served_route import note_route, route_for_outcome, serving_route_now
from assurance.workflow_chains import composition_for, composition_signal
from tests.signed_chains import ENGINE_KEYS

pytestmark = pytest.mark.django_db

User = get_user_model()


def _deployment():
    owner = User.objects.create_user(
        username=f"u{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )
    dep = Deployment.objects.create(name=f"route-{Deployment.objects.count()}", owner=owner)
    ApprovedWorkflow.objects.create(deployment=dep, slug="refund", name="Refund")
    return dep


def _model(dep, **route):
    """A serving component whose route fields are ``route``."""
    return Asset.objects.create(
        deployment=dep,
        kind=Asset.Kind.MODEL,
        name="assistant",
        identifier="assistant",
        metadata={"model": "gpt-x", **route},
    )


def _move_route(asset, **route):
    asset.metadata = {**asset.metadata, **route}
    asset.save(update_fields=["metadata"])


def _envelope(dep, status, observed_at, *, engine="athena", workflow="refund"):
    outcome = oc.build_outcome(
        deployment=str(dep.uuid),
        workflow=workflow,
        status=status,
        engine=engine,
        engine_version="1.0.0",
        run_id=f"run-{uuid.uuid4().hex[:8]}",
        evidence_digest="sha256:" + "ab" * 32,
        observed_at=observed_at,
        reason="" if status == oc.HELD else "the chain did not hold",
    )
    return oc.sign_outcome(outcome, ENGINE_KEYS[engine])


def _ingest(dep, *envelopes, now):
    rows, refusals = observed_outcomes.ingest(dep, list(envelopes), now=now)
    assert refusals == [], refusals
    return rows


# ------------------------------------------------------------------ the change


def test_a_route_change_reopens_the_chain_that_ran_on_it_and_no_claim(engine_keyring):
    t0 = timezone.now() - timedelta(hours=3)
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    (row,) = _ingest(dep, _envelope(dep, oc.HELD, t0 + timedelta(minutes=5)), now=t0 + timedelta(minutes=6))
    assert row.route_fingerprint == serving_route_now(dep)
    assert composition_signal(dep) == comp.READY

    # The tokenizer changes. Nothing re-ran the chain.
    _move_route(model, tokenizer="tok-2")
    note_route(dep, now=t0 + timedelta(hours=1))

    composition = composition_for(dep)
    assert composition.off_route == ("refund",)
    assert composition.route_census[comp.ROUTE_MOVED] == 1
    assert composition.decision == comp.NEEDS_MORE_EVIDENCE
    assert composition.held_floored == ("refund",)
    assert "a run of another route is not a run of this one" in comp.explain(composition)
    assert "rests on no demonstrated exercise" not in comp.explain(composition)

    # Targeted: the chain is named as work, and no claim was re-opened for it.
    plan = plan_revalidation(dep)
    assert [w["workflow"] for w in plan["workflows_to_exercise"]] == ["refund"]
    assert plan["workflows_to_exercise"][0]["approved"] is True
    assert plan["summary"]["workflows_to_exercise"] == 1
    assert "Nothing needs to be re-run" not in plan["note"]
    assert check_invalidations(dep)["invalidated"] == 0


def test_exercising_the_chain_again_against_the_new_route_restores_it(engine_keyring):
    t0 = timezone.now() - timedelta(hours=3)
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    _ingest(dep, _envelope(dep, oc.HELD, t0 + timedelta(minutes=5)), now=t0 + timedelta(minutes=6))
    _move_route(model, tokenizer="tok-2")
    note_route(dep, now=t0 + timedelta(hours=1))
    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE

    after = t0 + timedelta(hours=2)
    _ingest(dep, _envelope(dep, oc.HELD, after), now=after + timedelta(minutes=1))
    composition = composition_for(dep)
    assert composition.off_route == ()
    assert composition.superseded == 1
    assert composition_signal(dep) == comp.READY


def test_a_violation_seen_on_a_route_that_changed_still_stands(engine_keyring):
    """A route change is not a fix. Only a later verdict can show one."""
    t0 = timezone.now() - timedelta(hours=3)
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    _ingest(dep, _envelope(dep, oc.VIOLATED, t0 + timedelta(minutes=5)), now=t0 + timedelta(minutes=6))
    _move_route(model, tokenizer="tok-2")
    note_route(dep, now=t0 + timedelta(hours=1))
    assert composition_signal(dep) == comp.NOT_RECOMMENDED


def test_a_route_that_changes_back_makes_the_run_current_again(engine_keyring):
    """The binding is to a route, not to an instant: a run of A is a run of A."""
    t0 = timezone.now() - timedelta(hours=3)
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    _ingest(dep, _envelope(dep, oc.HELD, t0 + timedelta(minutes=5)), now=t0 + timedelta(minutes=6))
    _move_route(model, tokenizer="tok-2")
    note_route(dep, now=t0 + timedelta(hours=1))
    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE
    _move_route(model, tokenizer="tok-1")
    note_route(dep, now=t0 + timedelta(hours=2))
    assert composition_signal(dep) == comp.READY


# ------------------------------------------------------------------ the binding


def test_a_run_observed_before_the_route_serving_now_was_noted_is_bound_to_nothing(engine_keyring):
    """Ingested late -- after the route changed -- a run cannot be shown to have
    exercised the route that serves now, and it is not bound to it."""
    t0 = timezone.now() - timedelta(days=3)
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    observed = t0 + timedelta(hours=1)
    _move_route(model, tokenizer="tok-2")
    note_route(dep, now=t0 + timedelta(hours=2))

    (row,) = _ingest(dep, _envelope(dep, oc.HELD, observed), now=t0 + timedelta(days=1))
    assert row.route_fingerprint == ""
    composition = composition_for(dep)
    assert composition.route_census[comp.ROUTE_UNRECORDED] == 1
    assert composition.decision == comp.NEEDS_MORE_EVIDENCE


def test_a_change_no_refresh_noticed_is_noticed_at_the_binding(engine_keyring):
    """The note at the binding sees a route no refresh recorded, and a run from
    before it is not bound across the change."""
    t0 = timezone.now() - timedelta(days=1)
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    _move_route(model, tokenizer="tok-2")  # no note: no refresh ran
    (row,) = _ingest(dep, _envelope(dep, oc.HELD, t0 + timedelta(hours=1)), now=t0 + timedelta(hours=2))
    assert row.route_fingerprint == ""
    note = ServedRouteNote.objects.get(deployment=dep)
    assert note.fingerprint == serving_route_now(dep)
    assert note.since == t0 + timedelta(hours=2)


def test_noting_an_unchanged_route_leaves_its_instant_alone():
    t0 = timezone.now() - timedelta(days=1)
    dep = _deployment()
    _model(dep, tokenizer="tok-1")
    first = note_route(dep, now=t0)
    again = note_route(dep, now=t0 + timedelta(hours=5))
    assert first == again == (serving_route_now(dep), t0)


def test_a_new_deployment_starts_with_the_route_nothing_serves_noted():
    dep = _deployment()
    note = ServedRouteNote.objects.get(deployment=dep)
    assert note.fingerprint == serving_route_now(dep)
    assert note.since == dep.created_at


def test_an_undated_outcome_is_bound_to_nothing():
    dep = _deployment()
    assert route_for_outcome(dep, None, now=timezone.now()) == ""


def test_a_row_written_before_routes_were_bound_reads_unrecorded():
    dep = _deployment()
    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="refund", status=HELD, observed_at=timezone.now(), basis=comp.BASIS_UNKNOWN
    )
    assert composition_for(dep).route_census[comp.ROUTE_UNRECORDED] == 1


def test_the_refresh_notes_the_route_a_write_left_serving():
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    _move_route(model, tokenizer="tok-2")
    refresh_stored_decisions([dep.pk])
    assert ServedRouteNote.objects.get(deployment=dep).fingerprint == serving_route_now(dep)


def test_a_failed_note_never_fails_the_refresh(monkeypatch):
    from assurance import served_route

    def _broken(*args, **kwargs):
        raise RuntimeError("the note failed")

    monkeypatch.setattr(served_route, "note_route", _broken)
    dep = _deployment()
    refresh_stored_decisions([dep.pk])  # does not raise


def test_the_published_row_says_whether_it_was_taken_against_the_route_serving_now(engine_keyring):
    from assurance.serializers import WorkflowChainOutcomeSerializer

    t0 = timezone.now() - timedelta(hours=3)
    dep = _deployment()
    model = _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    (row,) = _ingest(dep, _envelope(dep, oc.HELD, t0 + timedelta(minutes=5)), now=t0 + timedelta(minutes=6))
    assert WorkflowChainOutcomeSerializer(row).data["route"] == comp.ROUTE_CURRENT
    _move_route(model, tokenizer="tok-2")
    assert WorkflowChainOutcomeSerializer(row).data["route"] == comp.ROUTE_MOVED


# ------------------------------------------------------------------ the rule


def _held(route, *, basis=comp.BASIS_DEMONSTRATED, signer="athena", at=None, workflow="refund"):
    return ChainOutcome(workflow, HELD, observed_at=at, basis=basis, signer=signer, route=route)


@pytest.mark.parametrize("route", sorted(comp.OFF_ROUTE))
def test_a_held_off_the_serving_route_floors_an_approved_workflow_only(route):
    assert compose([_held(route)], expected_workflows=["refund"]).decision == comp.NEEDS_MORE_EVIDENCE
    # No approved list: the composition speaks for no deployment, and gives no floor.
    assert compose([_held(route)]).decision == comp.READY


def test_a_route_this_module_does_not_define_is_refused():
    with pytest.raises(comp.UnknownChainRoute):
        _held("current-ish")


def test_the_default_route_is_unrecorded_never_current():
    assert ChainOutcome("refund", HELD).route == comp.ROUTE_UNRECORDED


def test_a_run_of_the_route_serving_now_wins_a_tie_whatever_arrived_first():
    at = timezone.now() - timedelta(hours=1)
    for order in ((comp.ROUTE_MOVED, comp.ROUTE_CURRENT), (comp.ROUTE_CURRENT, comp.ROUTE_MOVED)):
        result = compose([_held(route, at=at) for route in order], expected_workflows=["refund"])
        assert result.off_route == ()
        assert result.decision == comp.READY


def test_the_route_census_carries_every_reading_including_the_zeros():
    result = compose([_held(comp.ROUTE_CURRENT)], expected_workflows=["refund"])
    assert result.route_census == {comp.ROUTE_CURRENT: 1, comp.ROUTE_MOVED: 0, comp.ROUTE_UNRECORDED: 0}


def test_a_violated_off_the_serving_route_keeps_its_own_floor():
    violated = ChainOutcome(
        "refund", VIOLATED, basis=comp.BASIS_DEMONSTRATED, signer="athena", route=comp.ROUTE_MOVED
    )
    assert compose([violated], expected_workflows=["refund"]).decision == comp.NOT_RECOMMENDED


# ------------------------------------------------------------------ round 1 of #105


def _accepted(dep, *, severity, accepted_at):
    return Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{uuid.uuid4().hex[:6]}",
        finding_type="t",
        title="accepted",
        severity=severity,
        status=Finding.Status.ACCEPTED,
        risk_accepted_until=timezone.now() + timedelta(days=30),
        risk_accepted_severity=accepted_at,
    )


def test_an_acceptance_given_at_medium_does_not_cover_a_critical():
    """The next scan reported the same signature as critical: ingest refreshed the
    severity and left the status alone. A medium someone chose to carry is not a
    critical they chose to carry."""
    dep = _deployment()
    finding = _accepted(dep, severity="medium", accepted_at="medium")
    now = timezone.now()
    assert accepted_risk_signal(dep, now=now)["cap"] == Deployment.Decision.READY_RESTRICTED
    Finding.objects.filter(pk=finding.pk).update(severity="critical")
    signal = accepted_risk_signal(dep, now=now)
    assert signal["cap"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [f.pk for f in signal["lapsed"]] == [finding.pk]


@pytest.mark.parametrize("accepted_at", ["", "severe", None])
def test_an_acceptance_that_does_not_say_what_it_covered_covers_nothing(accepted_at):
    dep = _deployment()
    _accepted(dep, severity="low", accepted_at=accepted_at or "")
    assert accepted_risk_signal(dep, now=timezone.now())["cap"] == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_an_acceptance_covers_a_severity_that_fell():
    dep = _deployment()
    _accepted(dep, severity="low", accepted_at="high")
    assert accepted_risk_signal(dep, now=timezone.now())["cap"] == Deployment.Decision.READY_RESTRICTED


def test_accepting_through_the_route_records_the_severity_it_covers():
    from assurance.serializers import FindingSerializer

    dep = _deployment()
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp-route", finding_type="t", title="t", severity="high"
    )
    serializer = FindingSerializer(
        finding,
        data={"status": Finding.Status.ACCEPTED, "risk_accepted_until": timezone.now() + timedelta(days=5)},
        partial=True,
    )
    assert serializer.is_valid(), serializer.errors
    serializer.save()
    finding.refresh_from_db()
    assert finding.risk_accepted_severity == "high"

    reopened = FindingSerializer(finding, data={"status": Finding.Status.OPEN}, partial=True)
    assert reopened.is_valid(), reopened.errors
    reopened.save()
    finding.refresh_from_db()
    assert finding.risk_accepted_severity == ""


def test_the_admin_names_a_decision_whose_inputs_moved_with_time():
    from django.contrib import admin as django_admin

    from assurance.admin import DeploymentAdmin

    dep = _deployment()
    Deployment.objects.filter(pk=dep.pk).update(
        decision=Deployment.Decision.READY_RESTRICTED,
        decision_valid_until=timezone.now() - timedelta(seconds=1),
    )
    dep.refresh_from_db()
    shown = DeploymentAdmin(Deployment, django_admin.site).decision_in_force(dep)
    assert shown.startswith(Deployment.Decision.READY_RESTRICTED.label)
    assert "lapsed" in shown


def test_the_route_rule_moves_the_policy_pin_so_stored_decisions_are_recomputed():
    """The route rule changes what stored chains imply without a write. It is named
    in the policy document, so the pin moves with it and every decision stamped
    under the pin before is recomputed (Deployment.decision_policy)."""
    from assurance.policy import POLICY

    caps = POLICY["decision"]["chain_caps"]
    assert caps["held_off_route"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert caps["held_on_unclassified_signer"] == Deployment.Decision.READY_RESTRICTED
    assert POLICY["decision"]["accepted_risk_caps"]["lapsed_undated_or_outgrown"] == (
        Deployment.Decision.NEEDS_MORE_EVIDENCE
    )


# ------------------------------------------------------------------ round 2 of #105


def _planned(monkeypatch, dep, outcomes, approved=("refund",)):
    """The plan for ``dep`` over ``outcomes`` as the chains it reads."""
    from assurance import revalidation

    composition = compose(outcomes, expected_workflows=list(approved))
    monkeypatch.setattr(revalidation, "composition_for", lambda deployment, *a, **k: composition)
    return plan_revalidation(dep)


def test_a_stronger_held_off_the_serving_route_is_work_beside_a_permit_check_on_it(monkeypatch):
    """A scan held for the workflow on a route nothing can bind, and Achilles' permit
    check held on the route that serves: both stand, and the rank picked the permit
    check. The plan was computed from that one alone, so it named nothing to
    exercise, while the only exercise of the serving route is a permit check."""
    scan = _held(comp.ROUTE_UNRECORDED, signer="athena")  # undated: nothing displaces it
    permit = _held(comp.ROUTE_CURRENT, signer="achilles", at=timezone.now() - timedelta(hours=1))
    result = compose([scan, permit], expected_workflows=["refund"])
    assert result.authorization_checked == ("refund",)
    assert result.off_route == ("refund",)

    plan = _planned(monkeypatch, _deployment(), [scan, permit])
    assert [w["workflow"] for w in plan["workflows_to_exercise"]] == ["refund"]
    assert plan["summary"]["workflows_to_exercise"] == 1
    assert "Nothing needs to be re-run" not in plan["note"]


def test_a_held_off_the_serving_route_is_no_work_beside_one_as_strong_on_it():
    at = timezone.now() - timedelta(hours=1)
    for weaker in (_held(comp.ROUTE_MOVED, signer="achilles", at=at), _held(comp.ROUTE_MOVED, at=at)):
        result = compose([weaker, _held(comp.ROUTE_CURRENT, at=at)], expected_workflows=["refund"])
        assert result.off_route == ()


@pytest.mark.parametrize("later", ["a weaker held on the serving route", "a violation on it"])
def test_a_held_off_the_serving_route_a_later_verdict_superseded_is_no_work(monkeypatch, later):
    """Only what survives is read: a scan of a route that is gone, displaced by a
    later demonstrated verdict on the route serving now, is history, not work. Read
    over every attempt, the plan named it -- beside a later permit check it would
    otherwise be weaker than, or a violation that already floors the workflow."""
    at = timezone.now() - timedelta(hours=2)
    old = _held(comp.ROUTE_MOVED, signer="athena", at=at)
    if later == "a weaker held on the serving route":
        newer = _held(comp.ROUTE_CURRENT, signer="achilles", at=at + timedelta(hours=1))
    else:
        newer = ChainOutcome(
            "refund", VIOLATED, observed_at=at + timedelta(hours=1), basis=comp.BASIS_DEMONSTRATED,
            signer="athena", route=comp.ROUTE_CURRENT,
        )

    assert compose([old, newer], expected_workflows=["refund"]).off_route == ()
    assert _planned(monkeypatch, _deployment(), [old, newer])["workflows_to_exercise"] == []


@pytest.mark.parametrize("route", sorted(comp.OFF_ROUTE))
def test_the_plan_names_every_held_chain_off_the_serving_route_approved_or_not(monkeypatch, route):
    plan = _planned(monkeypatch, _deployment(), [_held(route), _held(route, workflow="export")])
    assert {(w["workflow"], w["approved"]) for w in plan["workflows_to_exercise"]} == {
        ("refund", True),
        ("export", False),
    }


def test_a_release_that_changes_what_a_served_route_is_moves_the_policy_pin(engine_keyring, monkeypatch):
    """The route axis compares the route each outcome was bound to with the route the
    definition reads off the graph now, so a release that changes the definition --
    its version, its fields, the metadata key each is read from -- moves every route,
    and the decision of the same stored rows. The pin did not move with it (#105 round
    4): the stored READY stayed stamped as current and was published."""
    from assurance import served_route
    from assurance.decision import compute_decision, current_decision, recompute_decision, stamped_in_force
    from assurance.policy import policy_pin

    t0 = timezone.now() - timedelta(hours=3)
    dep = _deployment()
    _model(dep, tokenizer="tok-1")
    note_route(dep, now=t0)
    _ingest(dep, _envelope(dep, oc.HELD, t0 + timedelta(minutes=5)), now=t0 + timedelta(minutes=6))
    stored = recompute_decision(Deployment.objects.get(pk=dep.pk))
    pin = policy_pin()

    monkeypatch.setattr(served_route, "ROUTE_VERSION", "mythos.assurance.served-route/2")

    computed = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert computed != stored
    assert policy_pin() != pin, "the route definition moved the decision and not the pin"
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == computed
