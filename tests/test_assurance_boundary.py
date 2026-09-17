"""Athena Phase 1.4 — AI Data Boundary Assessment.

Proves the assessment reconciles the *approved* data boundary a human declares
against the deployment's *actual* data destinations (its provider/tool assets and
their declared postures): a region outside the boundary or a provider that trains
on data when the boundary forbids it is a violation; a posture nobody declared is
an unknown (a gap, never a pass, never a violation); an unmanaged data sink is a
shadow destination outside the boundary. Writes are admin-only, reads open, and
an undeclared boundary never reads as permission.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import boundary
from assurance.models import Asset, DataBoundary, Deployment, EvidenceClass, Provider, ProviderAssertion
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name, kind=Provider.Kind.MODEL_PROVIDER, **assertions):
    p = Provider.objects.create(name=name, kind=kind)
    for field, value in assertions.items():
        ProviderAssertion.objects.create(
            provider=p, field=field, value=value, evidence_class=EvidenceClass.VENDOR_ASSERTED
        )
    return p


def _asset(dep, provider=None, kind=Asset.Kind.MODEL, classification=Asset.Classification.KNOWN, name="m", identifier=None):
    return Asset.objects.create(
        deployment=dep, provider=provider, kind=kind, classification=classification,
        name=name, identifier=identifier or name,
    )


def _policy(dep, **kwargs):
    return DataBoundary.objects.create(deployment=dep, **kwargs)


def test_region_outside_the_boundary_is_a_violation():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", region="us-east-1", trains_on_data="No — zero retention")
    _asset(dep, provider=p, name="gpt-x")
    _policy(dep, allowed_regions=["eu-west-1", "eu"])

    result = boundary.assess_boundary(dep)
    flow = result["flows"][0]
    assert flow["status"] == "violation"
    assert any("us-east-1" in r for r in flow["violations"])
    assert result["summary"]["violations"] == 1


def test_region_within_the_boundary_is_approved():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("EU Model Co", region="eu-west-1", trains_on_data="No")
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["eu"])

    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "approved"


def test_training_when_forbidden_is_a_violation_but_a_negation_is_not():
    dep = Deployment.objects.create(name="d", owner=_user())
    trains = _provider("Trainer", trains_on_data="Yes, on customer data")
    optedout = _provider("Clean", trains_on_data="No — opted out")
    _asset(dep, provider=trains, name="a")
    _asset(dep, provider=optedout, name="b")
    _policy(dep, training_allowed=False)

    flows = {f["provider_name"]: f for f in boundary.assess_boundary(dep)["flows"]}
    assert flows["Trainer"]["status"] == "violation"
    assert any("trains on customer data" in r for r in flows["Trainer"]["violations"])
    # "No — opted out" must not be read as affirmative → no violation.
    assert flows["Clean"]["status"] == "approved"


def test_undeclared_posture_is_an_unknown_not_a_violation():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Silent")  # declares nothing
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["eu"], training_allowed=False)

    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "unknown"
    assert flow["violations"] == []
    assert any("region" in u for u in flow["unknowns"])
    assert any("training" in u for u in flow["unknowns"])


def test_no_declared_boundary_never_reads_as_permission():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", region="us-east-1", trains_on_data="Yes")
    _asset(dep, provider=p, name="m")
    # No DataBoundary declared.
    result = boundary.assess_boundary(dep)
    assert result["declared"] is False
    assert result["flows"][0]["status"] == "unknown"  # not "approved"


def test_unmanaged_data_sink_is_a_shadow_destination():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, provider=None, kind=Asset.Kind.MCP_SERVER,
           classification=Asset.Classification.UNMANAGED, name="shadow-mcp", identifier="mcp://rogue")
    _policy(dep, allowed_regions=["eu"])

    result = boundary.assess_boundary(dep)
    assert result["summary"]["shadow_destinations"] == 1
    assert result["shadow_destinations"][0]["asset_name"] == "shadow-mcp"


def test_data_boundary_api_get_and_admin_put():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    p = _provider("OpenAI", region="us-east-1")
    _asset(dep, provider=p, name="gpt-x")

    factory = APIRequestFactory()

    # GET before any boundary: undeclared, open to any operator.
    get_view = DeploymentViewSet.as_view({"get": "data_boundary"})
    analyst = _user("ana", role=User.Roles.ANALYST)
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/data-boundary/")
    force_authenticate(req, user=analyst)
    resp = get_view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["declared"] is False

    # PUT is admin-only.
    put_view = DeploymentViewSet.as_view({"put": "data_boundary"})
    denied = factory.put(
        f"/api/assurance/deployments/{dep.uuid}/data-boundary/",
        {"allowed_regions": ["eu"], "training_allowed": False}, format="json",
    )
    force_authenticate(denied, user=analyst)
    assert put_view(denied, uuid=str(dep.uuid)).status_code == 403

    ok = factory.put(
        f"/api/assurance/deployments/{dep.uuid}/data-boundary/",
        {"allowed_regions": ["eu"], "training_allowed": False}, format="json",
    )
    force_authenticate(ok, user=admin)
    resp = put_view(ok, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["declared"] is True
    # The us-east-1 provider now violates the eu-only boundary.
    assert resp.data["summary"]["violations"] == 1
    assert DataBoundary.objects.get(deployment=dep).allowed_regions == ["eu"]
