"""Every write route either keeps the stored decision current or cannot move it.

Round seven found four routes that wrote a decision input and never refreshed the
stored decision -- a finding's status, the declared architecture, the drift
findings, the invalidation check -- and three that refreshed it in a second
transaction after the write had committed. Each was found by reading one route.
The next route will be added by someone who has not read this, so the list of
routes is taken from the URL resolver rather than written down: a mutating route
this file does not account for fails the first test below, and the author has to
say which kind it is.

A route that MOVES the decision is performed, and then every surface that publishes
the decision must publish one -- and a different one from before, so the agreement
is not the vacuous kind. It is performed again with the refresh made to fail, and
the write must not be recorded: that is what "in the same transaction" means, and
it is the only outside view of it.

A route that CANNOT move the decision says why, and is performed with every model
the decision is computed from watched: it must write none of them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django.contrib.auth import get_user_model
from django.db.models.signals import post_delete, post_save
from django.urls import URLResolver, get_resolver
from django.utils import timezone
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import signals
from assurance.decision import recompute_decision
from assurance.models import (
    ApprovedWorkflow,
    Asset,
    AssuranceClaim,
    ConnectorBinding,
    DeclaredComponent,
    Deployment,
    EvidenceClass,
    Finding,
    PostureBinding,
    Provider,
    ProviderAssertion,
    Unknown,
)
from tests.decision_surfaces import one_decision
from tests.signed_chains import ENGINE_KEYS, record_signed

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
MUTATING = frozenset({"post", "put", "patch", "delete"})


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _client():
    client = APIClient()
    client.force_authenticate(user=_admin())
    return client


def _base(dep):
    return f"/api/assurance/deployments/{dep.uuid}/"


def _scanned(name="d"):
    """A deployment a complete scan found nothing on: READY, stored and current."""
    dep = Deployment.objects.create(name=f"{name}{Deployment.objects.count()}", owner=_admin())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    recompute_decision(dep)
    return dep


def _approved(dep, slug="refund-over-limit"):
    ApprovedWorkflow.objects.create(deployment=dep, slug=slug, name=slug)


# ------------------------------------------------ the routes that move the decision
#
# Each returns the deployment, its stored decision brought current, and the write.


def _pause():
    dep = _scanned()
    return dep, lambda c: c.post(_base(dep) + "recompute/", {"paused": True}, format="json")


def _approve_a_workflow_nobody_ran():
    dep = _scanned()
    return dep, lambda c: c.put(
        _base(dep) + "approved-workflows/",
        {"workflows": [{"slug": "refund-over-limit", "name": "Refund"}]},
        format="json",
    )


def _type_in_a_violation():
    dep = _scanned()
    _approved(dep)
    recompute_decision(dep)
    return dep, lambda c: c.post(
        _base(dep) + "chain-outcomes/",
        {"workflow": "refund-over-limit", "status": "violated", "observed_at": timezone.now().isoformat()},
        format="json",
    )


def _sign_a_violation():
    dep = _scanned()
    _approved(dep)
    recompute_decision(dep)
    envelope = oc.sign_outcome(
        oc.build_outcome(
            deployment=str(dep.uuid),
            workflow="refund-over-limit",
            status=oc.VIOLATED,
            engine="achilles",
            engine_version="1.0.0",
            run_id="run-meta",
            evidence_digest="sha256:" + "ab" * 32,
            observed_at=datetime.now(dt_timezone.utc) - timedelta(minutes=1),
            reason="the gate refused the dispatch",
        ),
        ENGINE_KEYS["achilles"],
    )
    return dep, lambda c: c.post(_base(dep) + "chain-outcomes/observed/", envelope, format="json")


def _declare_a_component_nobody_observed():
    dep = _scanned()
    return dep, lambda c: c.put(
        _base(dep) + "declared-architecture/",
        {"components": [{"kind": "model", "name": "never-observed"}]},
        format="json",
    )


def _record_drift():
    dep = _scanned()
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt")
    for name in ("gpt", "shadow-llm"):
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.MODEL, classification=Asset.Classification.KNOWN,
            name=name, identifier=name, assessed_at=timezone.now(),
        )
    recompute_decision(dep)
    return dep, lambda c: c.post(_base(dep) + "record-bom-drift/")


def _re_derive_the_claims():
    dep = Deployment.objects.create(name="claims", owner=_admin())
    _approved(dep)
    record_signed(dep, "refund-over-limit", oc.HELD, datetime.now(dt_timezone.utc) - timedelta(minutes=5))
    recompute_decision(dep)
    return dep, lambda c: c.post(_base(dep) + "recompute-claims/")


def _passing_claims(dep):
    from assurance.claims import derive_claims

    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).update(
        status=AssuranceClaim.ClaimStatus.SUPPORTED
    )


def _invalidate_the_claims():
    dep = _scanned()
    provider = Provider.objects.create(name="OpenAI", kind=Provider.Kind.MODEL_PROVIDER)
    ProviderAssertion.objects.create(
        provider=provider, field="region", value="eu-west-1",
        evidence_class=EvidenceClass.CONFIGURATION_VERIFIED,
    )
    Asset.objects.create(
        deployment=dep, provider=provider, kind=Asset.Kind.MODEL,
        classification=Asset.Classification.KNOWN, name="gpt", identifier="gpt",
        metadata={"region": "eu-west-1"},
    )
    _passing_claims(dep)
    # The system moves after the claims were derived, as an ingest moves it.
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.VECTOR_DB, classification=Asset.Classification.KNOWN,
        name="pinecone", identifier="pinecone",
    )
    recompute_decision(dep)
    return dep, lambda c: c.post(_base(dep) + "check-invalidations/")


def _contradict_a_claim():
    dep = _scanned()
    _passing_claims(dep)
    recompute_decision(dep)
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).first()
    return dep, lambda c: c.post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "contradicted"}, format="json"
    )


def _reopen_a_critical_finding():
    dep = _scanned()
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp-critical", finding_type="t", title="T",
        severity="critical", status=Finding.Status.CLOSED,
    )
    recompute_decision(dep)
    return dep, lambda c: c.patch(f"/api/assurance/findings/{finding.uuid}/", {"status": "open"}, format="json")


MOVES = {
    ("DeploymentViewSet", "recompute", "post"): _pause,
    ("DeploymentViewSet", "approved_workflows", "put"): _approve_a_workflow_nobody_ran,
    ("DeploymentViewSet", "chain_outcomes", "post"): _type_in_a_violation,
    ("DeploymentViewSet", "observed_chain_outcomes", "post"): _sign_a_violation,
    ("DeploymentViewSet", "declared_architecture", "put"): _declare_a_component_nobody_observed,
    ("DeploymentViewSet", "record_bom_drift", "post"): _record_drift,
    ("DeploymentViewSet", "recompute_claims", "post"): _re_derive_the_claims,
    ("DeploymentViewSet", "check_invalidations", "post"): _invalidate_the_claims,
    ("ClaimViewSet", "transition", "post"): _contradict_a_claim,
    ("FindingViewSet", "partial_update", "patch"): _reopen_a_critical_finding,
}


# ------------------------------------------------ the routes that cannot move it
#
# Each says WHY, and returns a deployment and a write the route accepts.


def _check():
    dep = _scanned()
    return dep, lambda c: c.post("/api/assurance/deployments/check/", {}, format="json")


def _chain_birth():
    dep = _scanned()
    return dep, lambda c: c.post(
        _base(dep) + "chain-birth/",
        {"chain": "scan", "birth_id": "b-1", "born_at": "2026-09-01T00:00:00Z", "seq": 1},
        format="json",
    )


def _finding(dep):
    return Finding.objects.create(
        deployment=dep, fingerprint="fp-low", finding_type="t", title="T", severity="low"
    )


def _connector_push():
    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    return dep, lambda c: c.post(_base(dep) + "connectors/jira/push/", {"finding": str(finding.uuid)}, format="json")


def _connector_config_put():
    dep = _scanned()
    return dep, lambda c: c.put(_base(dep) + "connectors/jira/config/", {"enabled": False}, format="json")


def _connector_config_delete():
    dep = _scanned()
    ConnectorBinding(deployment=dep, connector="jira", enabled=False).save()
    return dep, lambda c: c.delete(_base(dep) + "connectors/jira/config/")


def _posture_config_put():
    dep = _scanned()
    return dep, lambda c: c.put(_base(dep) + "posture/cloud/config/", {"enabled": False}, format="json")


def _posture_config_delete():
    dep = _scanned()
    PostureBinding(deployment=dep, domain="cloud", enabled=False).save()
    return dep, lambda c: c.delete(_base(dep) + "posture/cloud/config/")


def _dispatch_policy():
    dep = _scanned()
    return dep, lambda c: c.put(_base(dep) + "dispatch-policy/", {"enabled": False}, format="json")


def _data_boundary_put():
    dep = _scanned()
    return dep, lambda c: c.put(_base(dep) + "data-boundary/", {"training_allowed": False}, format="json")


def _data_boundary_patch():
    dep = _scanned()
    return dep, lambda c: c.patch(_base(dep) + "data-boundary/", {"notes": "reviewed"}, format="json")


def _remediation_transition():
    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    return dep, lambda c: c.post(
        f"/api/assurance/findings/{finding.uuid}/remediation/transition/", {"to_state": "triaged"}, format="json"
    )


def _remediation_assign():
    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    assignee = _admin()
    return dep, lambda c: c.post(
        f"/api/assurance/findings/{finding.uuid}/remediation/assign/", {"assignee": assignee.username}, format="json"
    )


def _provider_create():
    dep = _scanned()
    return dep, lambda c: c.post(
        "/api/assurance/providers/", {"name": "Anthropic", "kind": "model_provider"}, format="json"
    )


def _provider():
    return Provider.objects.create(name="OpenAI", kind=Provider.Kind.MODEL_PROVIDER)


def _provider_patch():
    dep = _scanned()
    provider = _provider()
    return dep, lambda c: c.patch(f"/api/assurance/providers/{provider.uuid}/", {"notes": "x"}, format="json")


def _assertion_create():
    dep = _scanned()
    provider = _provider()
    return dep, lambda c: c.post(
        "/api/assurance/provider-assertions/",
        {"provider": str(provider.uuid), "field": "region", "value": "eu", "evidence_class": "vendor_asserted"},
        format="json",
    )


def _assertion():
    return ProviderAssertion.objects.create(
        provider=_provider(), field="region", value="eu", evidence_class=EvidenceClass.VENDOR_ASSERTED
    )


def _assertion_patch():
    dep = _scanned()
    assertion = _assertion()
    return dep, lambda c: c.patch(
        f"/api/assurance/provider-assertions/{assertion.uuid}/", {"value": "us"}, format="json"
    )


def _assertion_delete():
    dep = _scanned()
    assertion = _assertion()
    return dep, lambda c: c.delete(f"/api/assurance/provider-assertions/{assertion.uuid}/")


def _unknown_patch():
    dep = _scanned()
    unknown = Unknown.objects.create(deployment=dep, fingerprint="u-1", question="Is it?")
    return dep, lambda c: c.patch(f"/api/assurance/unknowns/{unknown.uuid}/", {"notes": "asked"}, format="json")


_PROFILE = (
    "a provider's profile reaches the decision only through the claims derived from "
    "it, and those move on recompute-claims, which is accounted for above"
)

CANNOT_MOVE = {
    ("DeploymentViewSet", "check", "post"): (
        "reads every stream across the portfolio; it writes nothing but the reconcile "
        "every published read of the decision makes",
        _check,
    ),
    ("DeploymentViewSet", "chain_birth", "post"): (
        "records an engine chain's birth and raises an Unknown; the decision reads neither",
        _chain_birth,
    ),
    ("DeploymentViewSet", "connector_push", "post"): (
        "pushes a finding OUT to an external system; it changes nothing here",
        _connector_push,
    ),
    ("DeploymentViewSet", "connector_config", "put"): ("outbound wiring, not an assessment", _connector_config_put),
    ("DeploymentViewSet", "connector_config", "delete"): ("outbound wiring, not an assessment", _connector_config_delete),
    ("DeploymentViewSet", "posture_config", "put"): ("a credential binding, not an assessment", _posture_config_put),
    ("DeploymentViewSet", "posture_config", "delete"): ("a credential binding, not an assessment", _posture_config_delete),
    ("DeploymentViewSet", "dispatch_policy", "put"): (
        "says when findings are pushed out, never what they say",
        _dispatch_policy,
    ),
    ("DeploymentViewSet", "data_boundary", "put"): (
        "the approved boundary reaches the decision only through the claims derived "
        "from it, which move on recompute-claims, accounted for above",
        _data_boundary_put,
    ),
    ("DeploymentViewSet", "data_boundary", "patch"): (
        "as the PUT: through the claims, never directly",
        _data_boundary_patch,
    ),
    ("FindingViewSet", "remediation_transition", "post"): (
        "the remediation workflow is the human process of fixing a finding, never the "
        "security status the decision reads",
        _remediation_transition,
    ),
    ("FindingViewSet", "remediation_assign", "post"): (
        "who does the remediation work, not whether the risk is live",
        _remediation_assign,
    ),
    ("ProviderViewSet", "create", "post"): (_PROFILE, _provider_create),
    ("ProviderViewSet", "partial_update", "patch"): (_PROFILE, _provider_patch),
    ("ProviderAssertionViewSet", "create", "post"): (_PROFILE, _assertion_create),
    ("ProviderAssertionViewSet", "partial_update", "patch"): (_PROFILE, _assertion_patch),
    ("ProviderAssertionViewSet", "destroy", "delete"): (_PROFILE, _assertion_delete),
    ("UnknownViewSet", "partial_update", "patch"): (
        "the Unknowns register is reported beside the decision, never computed into it",
        _unknown_patch,
    ),
}


def _mutating_routes() -> set[tuple[str, str, str]]:
    """``(viewset, action, method)`` for every mutating route the project's URLconf
    serves from the assurance app, wherever it is mounted."""
    found = set()

    def walk(patterns):
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                walk(pattern.url_patterns)
                continue
            view = getattr(pattern.callback, "cls", None)
            if view is None or not view.__module__.startswith("assurance."):
                continue
            actions = getattr(pattern.callback, "actions", None)
            if actions is None:
                # A plain APIView: its handlers are its methods.
                actions = {m: m for m in MUTATING if hasattr(view, m)}
            for method, name in actions.items():
                # A method the router maps but the view refuses (`http_method_names`)
                # is a 405, not a route.
                if method in MUTATING and method in view.http_method_names:
                    found.add((view.__name__, name, method))

    walk(get_resolver().url_patterns)
    return found


def test_every_mutating_route_is_accounted_for():
    routes = _mutating_routes()
    assert routes, "the resolver walk found no assurance routes at all"
    assert not set(MOVES) & set(CANNOT_MOVE)
    unaccounted = routes - set(MOVES) - set(CANNOT_MOVE)
    assert not unaccounted, (
        f"{sorted(unaccounted)}: a mutating route this file does not know. If it can "
        "change what the decision is computed from, it must refresh the stored decision "
        "inside its own transaction and be added to MOVES; if it cannot, add it to "
        "CANNOT_MOVE and say why."
    )
    gone = (set(MOVES) | set(CANNOT_MOVE)) - routes
    assert not gone, f"{sorted(gone)}: listed here but no longer routed"


@pytest.mark.parametrize("route", sorted(MOVES), ids=lambda r: f"{r[0]}.{r[1]}.{r[2]}")
def test_a_route_that_moves_the_decision_leaves_every_surface_on_the_new_one(route):
    dep, write = MOVES[route]()
    client = _client()
    before = one_decision(dep, client)
    response = write(client)
    assert response.status_code < 300, response.content
    after = one_decision(dep, client)
    assert after != before, f"the write did not move the decision ({before}), so this proved nothing"


@pytest.mark.parametrize("route", sorted(MOVES), ids=lambda r: f"{r[0]}.{r[1]}.{r[2]}")
def test_a_write_whose_refresh_fails_is_not_recorded(route, monkeypatch):
    """The write and the refresh are one transaction: a refresh that fails (a lock
    timeout, "database is locked") takes the write with it. A write that stood
    without its refresh is the stale decision this file is about, and one a signed
    outcome's retry could never repair -- the envelope is refused as a replay."""
    from assurance import views

    dep, write = MOVES[route]()
    client = _client()
    before = one_decision(dep, client)

    def fails(deployment, **kwargs):
        raise RuntimeError("the refresh failed")

    real = views.recompute_decision
    monkeypatch.setattr(views, "recompute_decision", fails)
    client.raise_request_exception = False
    assert write(client).status_code == 500
    # Put back by hand: `monkeypatch.undo()` would also withdraw the keyring the
    # fixture configured, and move every signed chain's decision with it.
    monkeypatch.setattr(views, "recompute_decision", real)
    assert one_decision(dep, client) == before


@pytest.mark.parametrize("route", sorted(CANNOT_MOVE), ids=lambda r: f"{r[0]}.{r[1]}.{r[2]}")
def test_a_route_that_cannot_move_the_decision_writes_none_of_its_inputs(route):
    why, scenario = CANNOT_MOVE[route]
    assert why
    dep, write = scenario()
    client = _client()
    before = one_decision(dep, client)
    written = []

    def watch(sender, instance, **kwargs):
        # A delete always counts; a save counts when it writes a column the
        # decision reads -- not a finding's remediation state, not the reconcile a
        # published read makes of the deployment's own decision columns.
        fields = kwargs.get("update_fields")
        if "created" in kwargs and not signals.writes_a_decision_input(instance, fields):
            return
        written.append((sender.__name__, fields))

    # The deployment row too: `evidence_incomplete` and `last_complete_scan_at` are
    # inputs it carries itself.
    labels = [*signals.DECISION_INPUTS, "assurance.Deployment"]
    for label in labels:
        post_save.connect(watch, sender=label, dispatch_uid=f"meta-save:{label}")
        post_delete.connect(watch, sender=label, dispatch_uid=f"meta-delete:{label}")
    try:
        response = write(client)
    finally:
        for label in labels:
            post_save.disconnect(sender=label, dispatch_uid=f"meta-save:{label}")
            post_delete.disconnect(sender=label, dispatch_uid=f"meta-delete:{label}")
    assert response.status_code < 300, response.content
    assert written == [], f"{route} wrote a decision input: {written}"
    assert one_decision(dep, client) == before
