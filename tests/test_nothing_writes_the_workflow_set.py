"""The composition rule was wired into the decision, and nothing could fill it.

The previous change (``workflow_chains.py``) gave the compositional assurance
graph a caller: :func:`assurance.decision.decide` now folds a deployment's
composed chain outcomes into its decision. It shipped with two models and no way
to write to either. Over HTTP, every deployment therefore had:

* no approved workflows, so ``read_expected_workflows`` returned ``None`` and the
  composition could only ever speak for the chains it was handed;
* no chain outcomes, so it was handed none;
* and therefore a signal of ``None`` — which
  :func:`assurance.decision._worse` correctly never treats as good news, and
  which means the whole graph contributed **nothing to any real decision**.

That is one step better than the decorative control it replaced and still not
operational: a rule with a caller and no reachable input produces the same
number as a rule with no caller. So this file is about the INGEST PATH, and
about the one design decision it turns on.

THE APPROVED SET IS A DECLARATION; AN OUTCOME IS AN OBSERVATION.

``PUT /approved-workflows/`` replaces, because a set nobody can shrink is a set
nobody can correct, and a withdrawn approval has to be able to leave.
``POST /chain-outcomes/`` appends, because :func:`assurance.composition.compose`
reads a workflow's whole history to decide what stands and what a re-run
superseded. A replace there would leave exactly one outcome per workflow,
making supersession unreachable and handing the rule a single row to pick a
newest from. The rule would keep all of its logic and lose its input — which is
this codebase's recurring defect wearing the costume of a tidier endpoint.

Nothing here re-proves the rule. ``composition.py``'s own suite does that. What
is proved here is that a declaration and an observation reach it, that the two
write shapes are the two the rule needs, and that neither route quietly loses
what the other recorded.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import composition as comp
from assurance.decision import decision_support
from assurance.models import ApprovedWorkflow, Deployment, WorkflowChainOutcome
from assurance.views import DeploymentViewSet
from assurance.workflow_chains import composition_for, composition_signal

pytestmark = pytest.mark.django_db

User = get_user_model()

T1 = timezone.now() - timedelta(days=2)
T2 = timezone.now() - timedelta(days=1)


def _user(role=None, name=None):
    return User.objects.create_user(
        username=name or f"u{User.objects.count()}",
        password="x",
        role=role or User.Roles.ADMIN,
    )


def _client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


def _deployment(owner=None, name=None):
    owner = owner or _user()
    return Deployment.objects.create(
        name=name or f"deployment-{Deployment.objects.count()}", owner=owner
    )


def _approved_url(dep):
    return f"/api/assurance/deployments/{dep.uuid}/approved-workflows/"


def _outcomes_url(dep):
    return f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/"


def _declare(client, dep, *slugs):
    return client.put(
        _approved_url(dep),
        {"workflows": [{"slug": s, "name": s.replace("-", " ").title()} for s in slugs]},
        format="json",
    )


def _record(client, dep, workflow, status, observed_at=T1, **extra):
    body = {"workflow": workflow, "status": status, **extra}
    if observed_at is not None:
        body["observed_at"] = observed_at.isoformat()
    return client.post(_outcomes_url(dep), body, format="json")


# --------------------------------------------------------------------------
# Reachability. The packet route this repo shipped in Phase 2.10 was complete,
# correct and registered on a viewset nobody could route to; two routes that
# work and cannot be called are worth one test that calls them.
# --------------------------------------------------------------------------


def test_both_routes_are_reachable_over_the_real_url_conf():
    dep = _deployment()
    client = _client(dep.owner)
    assert client.get(_approved_url(dep)).status_code == 200
    assert client.get(_outcomes_url(dep)).status_code == 200


# --------------------------------------------------------------------------
# What a write tells you it did.
# --------------------------------------------------------------------------


def test_declaring_the_set_reports_what_it_did_to_the_graph():
    """A write that reports only itself is how a set that FAILS to close scope
    looks exactly like one that closes it."""
    dep = _deployment()
    client = _client(dep.owner)

    response = _declare(client, dep, "checkout", "refund", "support-reply")
    assert response.status_code == 200
    assert response.data["approved_count"] == 3

    composition = response.data["composition"]
    # The set is now recorded, so the rule can count coverage at all -- and it
    # immediately reports the three workflows nobody has exercised, rather than
    # reporting a freshly declared scope as satisfied.
    assert composition["workflows_expected"] == 3
    assert composition["workflows_unreported"] == 3
    assert composition["census"][comp.NOT_DEMONSTRATED] == 3
    # `not_demonstrated` carries a floor, so the chains are NOT ready, and the
    # signal says so in the same response as the write.
    assert composition["signal"] == comp.FLOORS[comp.NOT_DEMONSTRATED]
    assert composition["signal"] != comp.READY


def test_recording_every_approved_workflow_held_is_what_closes_the_scope():
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout", "refund")

    assert _record(client, dep, "checkout", comp.HELD).status_code == 200
    response = _record(client, dep, "refund", comp.HELD)
    assert response.status_code == 200

    composition = response.data["composition"]
    assert composition["workflows_expected"] == 2
    assert composition["workflows_unreported"] == 0
    assert composition["workflows_unapproved"] == 0
    assert composition["signal"] == comp.READY
    # And the same answer from the in-process path, so the route is not the only
    # thing that can see it.
    assert composition_signal(dep) == comp.READY


def test_one_held_chain_and_a_declared_set_of_fifty_is_not_ready():
    """The rule's own central refusal, reached through HTTP for the first time.

    With no approved set recorded this is the ``READY`` the seam has to withhold;
    with the set recorded it is a floor. Both halves have to come from the same
    route for the ingest path to be the thing that made the rule operational.
    """
    dep = _deployment()
    client = _client(dep.owner)
    _record(client, dep, "checkout", comp.HELD)

    # No declaration yet: the composition speaks for the one chain it was given
    # and the seam refuses to let that stand for the deployment.
    assert composition_for(dep).decision == comp.READY
    assert composition_signal(dep) is None

    response = _declare(client, dep, "checkout", *[f"wf-{n}" for n in range(49)])
    assert response.data["composition"]["workflows_expected"] == 50
    assert response.data["composition"]["signal"] != comp.READY
    assert response.data["composition"]["workflows_unreported"] == 49


# --------------------------------------------------------------------------
# Declaration semantics: replace.
# --------------------------------------------------------------------------


def test_put_replaces_the_set_rather_than_merging_into_it():
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout", "refund")

    response = _declare(client, dep, "refund")
    assert response.data["approved_count"] == 1
    assert [row["slug"] for row in response.data["approved"]] == ["refund"]
    assert set(ApprovedWorkflow.objects.values_list("slug", flat=True)) == {"refund"}
    # Coverage shrank with the scope. A merge would have left `checkout`
    # permanently unreported and the deployment permanently not-ready for a
    # workflow the customer withdrew.
    assert response.data["composition"]["workflows_expected"] == 1


def test_withdrawing_an_approval_keeps_its_measurements_and_counts_them():
    """The slug-not-foreign-key decision, exercised end to end.

    A ``ForeignKey(ApprovedWorkflow)`` would have made this a cascade delete: the
    replace in the PUT would erase the recorded outcomes for any withdrawn
    workflow, and the platform's memory of exercising it would be editable by
    changing the roster. It is a slug, so the measurement outlives the approval
    and shows up where it belongs -- as an outcome for a workflow nobody
    approved.
    """
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout", "shadow-workflow")
    _record(client, dep, "checkout", comp.HELD)
    _record(client, dep, "shadow-workflow", comp.VIOLATED)

    response = _declare(client, dep, "checkout")

    assert WorkflowChainOutcome.objects.filter(workflow="shadow-workflow").count() == 1
    composition = response.data["composition"]
    assert composition["workflows_expected"] == 1
    assert composition["workflows_unapproved"] == 1
    # The violation still stands and still floors the deployment. Un-approving a
    # workflow is not a way to un-violate it.
    assert composition["census"][comp.VIOLATED] == 1
    assert composition["signal"] == comp.FLOORS[comp.VIOLATED]


def test_two_entries_naming_one_workflow_are_refused():
    """The unique constraint would raise a 500 four frames down; the slug is the
    identity outcomes match on, so a duplicate silently drops a declaration."""
    dep = _deployment()
    response = _client(dep.owner).put(
        _approved_url(dep),
        {
            "workflows": [
                {"slug": "checkout", "name": "Checkout"},
                {"slug": "checkout", "name": "Checkout (v2)"},
            ]
        },
        format="json",
    )
    assert response.status_code == 400
    assert "workflows" in response.data
    assert ApprovedWorkflow.objects.count() == 0


# --------------------------------------------------------------------------
# Observation semantics: append. The load-bearing difference.
# --------------------------------------------------------------------------


def test_post_appends_so_a_re_run_supersedes_rather_than_overwrites():
    """The distinction this whole route exists to get right.

    Under a replace-on-write the two assertions below would read
    ``recorded_count == 1`` and ``superseded == 0``: the history would be one row
    deep, nothing could supersede anything, and
    :attr:`~assurance.composition.Composition.superseded` -- which the rule
    reports so a reader can tell a stale verdict from a current one -- would be
    structurally zero.
    """
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout")
    _record(client, dep, "checkout", comp.VIOLATED, observed_at=T1)
    response = _record(client, dep, "checkout", comp.HELD, observed_at=T2)

    assert response.data["recorded_count"] == 2
    composition = response.data["composition"]
    assert composition["superseded"] == 1
    # The newer verdict stands; the older one is superseded, not deleted.
    assert composition["census"][comp.HELD] == 1
    assert composition["census"][comp.VIOLATED] == 0
    assert WorkflowChainOutcome.objects.count() == 2


def test_a_later_run_that_could_not_finish_cannot_erase_a_recorded_violation():
    """Only a verdict supersedes a verdict — ``composition._surviving``'s rule,
    reached through the route that records them.

    This is the second reason the route appends. A replace would let an
    inconclusive re-run overwrite the row holding a violation, and the rule would
    never see the violation to refuse to drop it.
    """
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout")
    _record(client, dep, "checkout", comp.VIOLATED, observed_at=T1)
    response = _record(client, dep, "checkout", comp.INCOMPLETE, observed_at=T2)

    composition = response.data["composition"]
    assert composition["census"][comp.VIOLATED] == 1
    assert composition["superseded"] == 0
    assert composition["signal"] == comp.FLOORS[comp.VIOLATED]


def test_an_outcome_for_an_unapproved_workflow_is_accepted_and_counted():
    """Validating the slug against the approved set would read as tightening the
    contract and would make ``workflows_unapproved`` a number no input can
    reach. A chain exercising a workflow nobody approved is the thing this
    platform exists to notice."""
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout")
    _record(client, dep, "checkout", comp.HELD)
    response = _record(client, dep, "undeclared-side-channel", comp.HELD)

    assert response.status_code == 200
    composition = response.data["composition"]
    assert composition["workflows_unapproved"] == 1
    # Every approved workflow held, so the rule floors nothing -- and the seam
    # still withholds READY, because the scope is not closed.
    assert composition["rule_decision"] == comp.READY
    assert composition["signal"] is None


def test_an_undated_outcome_is_accepted_and_means_recency_unknown():
    dep = _deployment()
    client = _client(dep.owner)
    response = _record(client, dep, "checkout", comp.HELD, observed_at=None)
    assert response.status_code == 200
    assert response.data["outcomes"][0]["observed_at"] is None
    assert WorkflowChainOutcome.objects.get().observed_at is None


def test_naive_observed_at_is_made_aware_rather_than_reaching_the_rule():
    """Pins the mechanism ``WorkflowChainOutcomeSerializer`` relies on.

    ``ChainOutcome`` compares two instants to decide supersession and raises on a
    naive one. Nothing in the serializer rejects a naive datetime, because
    ``USE_TZ`` is on and DRF's ``enforce_timezone`` converts it first -- so a
    hand-written guard for it was unreachable and was removed. This test is what
    keeps that reasoning honest: turn ``USE_TZ`` off and it fails here, loudly,
    instead of reaching the rule with a datetime it cannot compare.
    """
    dep = _deployment()
    client = _client(dep.owner)
    response = client.post(
        _outcomes_url(dep),
        {"workflow": "checkout", "status": comp.HELD, "observed_at": "2026-01-02T03:04:05"},
        format="json",
    )
    assert response.status_code == 200
    stored = WorkflowChainOutcome.objects.get().observed_at
    assert stored is not None and stored.utcoffset() is not None
    # And the rule can therefore compare it, which is the property that matters.
    assert composition_for(dep).decision == comp.READY


def test_an_unknown_status_is_refused():
    dep = _deployment()
    response = _record(_client(dep.owner), dep, "checkout", "probably-fine")
    assert response.status_code == 400
    assert "status" in response.data
    assert WorkflowChainOutcome.objects.count() == 0


def test_an_outcome_must_name_its_workflow():
    dep = _deployment()
    response = _client(dep.owner).post(
        _outcomes_url(dep), {"status": comp.HELD}, format="json"
    )
    assert response.status_code == 400
    assert "workflow" in response.data
    assert WorkflowChainOutcome.objects.count() == 0


# --------------------------------------------------------------------------
# Bounds and shape.
# --------------------------------------------------------------------------


def test_the_outcome_list_is_bounded_and_says_how_much_it_left_out():
    """Outcomes are append-only, so this list grows for the life of a
    deployment. A bare ``Response`` does not pass through the project's
    pagination, so the bound and the honesty about it are this route's job."""
    dep = _deployment()
    size = DeploymentViewSet.CHAIN_OUTCOME_PAGE_SIZE
    WorkflowChainOutcome.objects.bulk_create(
        WorkflowChainOutcome(
            deployment=dep,
            workflow=f"wf-{n}",
            status=comp.HELD,
            observed_at=T1 + timedelta(seconds=n),
        )
        for n in range(size + 3)
    )
    response = _client(dep.owner).get(_outcomes_url(dep))

    assert response.data["returned"] == size
    assert len(response.data["outcomes"]) == size
    assert response.data["truncated"] is True
    assert response.data["page_size"] == size
    # The whole count, beside the bounded list. `len(outcomes)` must never be
    # usable as the number of outcomes.
    assert response.data["recorded_count"] == size + 3
    # The composition is computed over ALL of them, not over the page.
    assert response.data["composition"]["workflows_assessed"] == size + 3


def test_the_payload_shapes_are_pinned():
    """Both payloads are hand-built dicts. The vendor-packet audit found a
    hand-built payload with no pinned shape quietly growing a field that leaked a
    customer hostname; an exact field set is what makes an addition a decision."""
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout")
    outcome = _record(client, dep, "checkout", comp.HELD, source="campaign", note="n")

    approved = client.get(_approved_url(dep))
    assert set(approved.data) == {"approved", "approved_count", "composition"}
    assert set(approved.data["approved"][0]) == {
        "uuid",
        "slug",
        "name",
        "description",
        "approved_by",
        "approved_at",
    }

    assert set(outcome.data) == {
        "outcomes",
        "returned",
        "truncated",
        "page_size",
        "recorded_count",
        "composition",
    }
    assert set(outcome.data["outcomes"][0]) == {
        "uuid",
        "workflow",
        "status",
        "status_label",
        "observed_at",
        "recorded_at",
        "source",
        "note",
    }
    assert set(outcome.data["composition"]) == {
        "signal",
        "rule_decision",
        "census",
        "deciding",
        "workflows_assessed",
        "workflows_expected",
        "workflows_unreported",
        "workflows_unapproved",
        "superseded",
        "explanation",
    }
    # All four statuses, always, including the zeros: a census that omits the
    # zeros cannot be read as "none of these" rather than "not measured".
    assert set(outcome.data["composition"]["census"]) == set(comp.CHAIN_STATUSES)


def test_the_write_routes_and_the_decision_route_report_one_composition():
    """The two publishers of this block must not be able to disagree.

    Both call ``workflow_chains.composition_payload``. An operator who declares a
    set, reads ``workflows_expected: 2`` back from the write, and then reads
    ``workflows_expected: null`` from the decision route has been told two things
    about one deployment -- and two hand-written copies of one shape is how that
    happens.
    """
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout", "refund")
    recorded = _record(client, dep, "checkout", comp.VIOLATED)

    assert recorded.data["composition"] == decision_support(dep)["composition"]


# --------------------------------------------------------------------------
# Authorisation and scope.
# --------------------------------------------------------------------------


def test_a_viewer_may_read_the_set_but_not_declare_or_record():
    """Reads are deliberately broad in this API; writes change the shared record.

    A VIEWER, not an analyst: ``_is_privileged`` admits analysts to the whole
    read model, so an analyst cannot demonstrate a write refusal distinctly from
    a read one.
    """
    viewer = _user(User.Roles.VIEWER)
    dep = _deployment(owner=viewer)
    client = _client(viewer)

    assert client.get(_approved_url(dep)).status_code == 200
    assert client.get(_outcomes_url(dep)).status_code == 200
    assert _declare(client, dep, "checkout").status_code == 403
    assert _record(client, dep, "checkout", comp.HELD).status_code == 403
    assert ApprovedWorkflow.objects.count() == 0
    assert WorkflowChainOutcome.objects.count() == 0


def test_a_viewer_cannot_reach_another_owners_deployment_on_either_route():
    """The scoping mutation that survived 41 tests on the vendor-packet route.

    Both actions must resolve the deployment through ``get_object()`` so the
    viewset's per-user queryset applies. Fetching it by uuid directly would make
    one customer's approved workflows and chain history readable by any
    authenticated user.
    """
    theirs = _deployment()
    outsider = _client(_user(User.Roles.VIEWER, name="outsider"))
    assert outsider.get(_approved_url(theirs)).status_code == 404
    assert outsider.get(_outcomes_url(theirs)).status_code == 404


def test_an_anonymous_request_reaches_neither_route():
    dep = _deployment()
    anon = APIClient()
    assert anon.get(_approved_url(dep)).status_code in (401, 403)
    assert anon.put(_approved_url(dep), {"workflows": []}, format="json").status_code in (401, 403)
    assert anon.post(_outcomes_url(dep), {}, format="json").status_code in (401, 403)


def test_declaring_an_empty_set_is_a_recorded_empty_set_not_an_absent_one():
    """``None`` and ``[]`` mean different things to the rule, and the database
    cannot tell them apart -- so no rows reads as *not recorded*. That makes an
    explicitly empty declaration indistinguishable from never declaring, which is
    the conservative reading and is worth stating rather than discovering.
    """
    dep = _deployment()
    client = _client(dep.owner)
    _declare(client, dep, "checkout")
    response = client.put(_approved_url(dep), {"workflows": []}, format="json")

    assert response.status_code == 200
    assert response.data["approved_count"] == 0
    assert response.data["composition"]["workflows_expected"] is None


def test_a_batch_of_outcomes_is_recorded_in_one_request():
    """A campaign exercising twelve chains should not need twelve requests, and
    the batch is one transaction: a bad row records none of them."""
    dep = _deployment()
    client = _client(dep.owner)
    response = client.post(
        _outcomes_url(dep),
        [
            {"workflow": "checkout", "status": comp.HELD},
            {"workflow": "refund", "status": comp.VIOLATED},
        ],
        format="json",
    )
    assert response.status_code == 200
    assert response.data["recorded_count"] == 2
    assert response.data["composition"]["census"][comp.VIOLATED] == 1


def test_a_bad_row_in_a_batch_records_none_of_it_and_is_named_by_position():
    dep = _deployment()
    client = _client(dep.owner)
    response = client.post(
        _outcomes_url(dep),
        [
            {"workflow": "checkout", "status": comp.HELD},
            {"workflow": "refund", "status": "probably-fine"},
        ],
        format="json",
    )
    assert response.status_code == 400
    # Index-keyed, which is the right shape here: the caller sent a list, so the
    # position is something it can find in its own request.
    assert response.data[1]["status"]
    assert WorkflowChainOutcome.objects.count() == 0


def test_the_provenance_of_a_declaration_is_readable():
    """``approved_by`` was written and nothing could read it.

    A provenance field only the database can see is a record kept for an audit
    that cannot reach it. The approver is the requesting admin, not whatever the
    body claims, and it survives that account being deleted as ``None`` -- which
    means *the approver is gone*, not *nobody approved this*.
    """
    admin = _user(User.Roles.ADMIN, name="approver")
    dep = _deployment(owner=admin)
    client = _client(admin)
    _declare(client, dep, "checkout")

    row = client.get(_approved_url(dep)).data["approved"][0]
    assert row["approved_by"] == "approver"
    assert row["approved_at"] is not None

    ApprovedWorkflow.objects.update(approved_by=None)
    row = client.get(_approved_url(dep)).data["approved"][0]
    assert row["approved_by"] is None
    # The approval itself is still there. SET_NULL, not CASCADE: an approval whose
    # approver left is still an approval, and deleting it would silently shrink
    # the expected set.
    assert client.get(_approved_url(dep)).data["approved_count"] == 1


def test_when_a_chain_was_exercised_and_when_it_was_recorded_are_both_readable():
    """A backfilled month of history and a measurement taken this minute must not
    look the same. ``observed_at`` is the exercise; ``recorded_at`` is the write."""
    dep = _deployment()
    client = _client(dep.owner)
    response = _record(client, dep, "checkout", comp.HELD, observed_at=T1)

    row = response.data["outcomes"][0]
    assert row["observed_at"] is not None
    assert row["recorded_at"] is not None
    assert row["recorded_at"] > row["observed_at"]
