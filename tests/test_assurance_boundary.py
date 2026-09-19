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
    # Allow sharing so this isolates the region check (undeclared sharing under a
    # no-sharing boundary is its own unknown, covered separately).
    _policy(dep, allowed_regions=["eu"], third_party_sharing_allowed=True)

    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "approved"


def test_training_when_forbidden_is_a_violation_but_a_negation_is_not():
    dep = Deployment.objects.create(name="d", owner=_user())
    trains = _provider("Trainer", trains_on_data="Yes, on customer data")
    optedout = _provider("Clean", trains_on_data="No — opted out")
    _asset(dep, provider=trains, name="a")
    _asset(dep, provider=optedout, name="b")
    _policy(dep, training_allowed=False, third_party_sharing_allowed=True)

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


def test_affirmative_training_is_not_lost_to_an_incidental_negation_substring():
    """Regression: negations were substring-matched, so a real training
    declaration containing 'opt' ('opt-in') or 'no' ('now') read as approved —
    a false pass in the dangerous direction. It must now be a violation."""
    dep = Deployment.objects.create(name="d", owner=_user())
    optin = _provider("OptIn", trains_on_data="Yes, opt-in training is enabled")
    now = _provider("Now", trains_on_data="trains on data for now")
    _asset(dep, provider=optin, name="a")
    _asset(dep, provider=now, name="b")
    _policy(dep, training_allowed=False)

    flows = {f["provider_name"]: f for f in boundary.assess_boundary(dep)["flows"]}
    assert flows["OptIn"]["status"] == "violation"
    assert flows["Now"]["status"] == "violation"


def test_a_real_opt_out_is_still_not_a_violation():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Clean", trains_on_data="No — opted out of all training")
    _asset(dep, provider=p, name="m")
    _policy(dep, training_allowed=False, third_party_sharing_allowed=True)
    assert boundary.assess_boundary(dep)["flows"][0]["status"] == "approved"


def test_region_is_not_approved_by_an_accidental_substring():
    """Regression: two-way substring approved 'aus-east' under an ['us'] boundary
    because 'us' is a substring. A region must match exactly or as a delimited
    sub-region, so this is now a violation."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Elsewhere", region="aus-east-1", trains_on_data="No")
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["us"])
    assert boundary.assess_boundary(dep)["flows"][0]["status"] == "violation"


def test_a_delimited_subregion_is_still_within_boundary():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("EU", region="eu-west-1", trains_on_data="No")
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["eu"], third_party_sharing_allowed=True)
    assert boundary.assess_boundary(dep)["flows"][0]["status"] == "approved"


def test_third_party_sharing_forbidden_but_declared_subprocessors_is_a_violation():
    """Regression: third_party_sharing_allowed was surfaced but never enforced. A
    provider declaring subprocessors under a no-sharing boundary must violate."""
    dep = Deployment.objects.create(name="d", owner=_user())
    shares = _provider("Shares", subprocessors="AWS, Cloudflare, Datadog")
    clean = _provider("NoShare", subprocessors="None — no subprocessors")
    _asset(dep, provider=shares, name="a")
    _asset(dep, provider=clean, name="b")
    # Allow training so only the sharing branch is exercised; forbid sharing.
    _policy(dep, training_allowed=True, third_party_sharing_allowed=False)

    flows = {f["provider_name"]: f for f in boundary.assess_boundary(dep)["flows"]}
    assert flows["Shares"]["status"] == "violation"
    assert any("subprocessor" in v for v in flows["Shares"]["violations"])
    # A declared "no subprocessors" is not a sharing violation.
    assert flows["NoShare"]["status"] == "approved"


def test_undeclared_sharing_posture_is_an_unknown_not_a_pass():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Silent")  # no subprocessors assertion
    _asset(dep, provider=p, name="m")
    _policy(dep, training_allowed=True, third_party_sharing_allowed=False)
    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "unknown"
    assert any("sharing" in u or "subprocessor" in u for u in flow["unknowns"])


@pytest.mark.parametrize(
    "declaration",
    [
        "Internal only",
        "internal use only",
        "in-house",
        "In-House",
        "first-party",
        "first party",
        "self-hosted",
        "on-premise",
        "on-premises",
        "kept internal",
        "company internal systems",
        "our own infrastructure",
        "internal",
        "internally only",
        "private",
    ],
)
def test_internal_only_subprocessors_is_not_a_sharing_violation(declaration):
    """Regression: a benign internal-only subprocessors declaration carries no
    negation token, so it used to read as third-party sharing and produce a false
    violation. An in-house declaration must now be approved, not flagged."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("InHouse", subprocessors=declaration)
    _asset(dep, provider=p, name="m")
    # Allow training so only the sharing branch is exercised; forbid sharing.
    _policy(dep, training_allowed=True, third_party_sharing_allowed=False)
    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "approved", flow["violations"]


@pytest.mark.parametrize(
    "declaration",
    [
        "AWS, OpenAI, Datadog",
        "third party",
        "third-party analytics vendors",
        "shares with third parties",
        "Stripe",
        "internal team and Stripe",  # an internal claim that also names a vendor
        "shared with external partners",
    ],
)
def test_a_real_sharing_declaration_is_still_a_violation(declaration):
    """The internal-only guard must never suppress a genuine sharing declaration:
    a named vendor, an affirmative "shares with third parties", or an internal
    claim that also names an external party still violates a no-sharing boundary."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Shares", subprocessors=declaration)
    _asset(dep, provider=p, name="m")
    _policy(dep, training_allowed=True, third_party_sharing_allowed=False)
    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "violation", declaration
    assert any("subprocessor" in v for v in flow["violations"])


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


# --- L3: PUT is a true replace, PATCH is the merge path ----------------------


def test_put_is_a_true_replace_and_clears_omitted_fields():
    """L3: PUT declares the whole boundary. A field left out of the body returns to
    its model default — an earlier "training allowed / sharing allowed" is never
    silently inherited when a later PUT omits it. Silence is not consent."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    _policy(dep, allowed_regions=["us"], training_allowed=True,
            third_party_sharing_allowed=True, notes="legacy")

    factory = APIRequestFactory()
    put_view = DeploymentViewSet.as_view({"put": "data_boundary"})
    req = factory.put(
        f"/api/assurance/deployments/{dep.uuid}/data-boundary/",
        {"allowed_regions": ["eu"]}, format="json",
    )
    force_authenticate(req, user=admin)
    assert put_view(req, uuid=str(dep.uuid)).status_code == 200

    b = DataBoundary.objects.get(deployment=dep)
    assert b.allowed_regions == ["eu"]              # the one field declared
    assert b.training_allowed is False              # omitted -> reset to default
    assert b.third_party_sharing_allowed is False   # omitted -> reset to default
    assert b.notes == ""                            # omitted -> reset to default


def test_put_with_an_empty_body_resets_to_the_safe_default():
    """A PUT with no fields declares the empty boundary: no region restriction,
    training and sharing denied — the most-restrictive posture, not a carry-over."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    _policy(dep, allowed_regions=["us"], training_allowed=True,
            third_party_sharing_allowed=True, notes="legacy")

    factory = APIRequestFactory()
    put_view = DeploymentViewSet.as_view({"put": "data_boundary"})
    req = factory.put(f"/api/assurance/deployments/{dep.uuid}/data-boundary/", {}, format="json")
    force_authenticate(req, user=admin)
    assert put_view(req, uuid=str(dep.uuid)).status_code == 200

    b = DataBoundary.objects.get(deployment=dep)
    assert b.allowed_regions == []
    assert b.training_allowed is False
    assert b.third_party_sharing_allowed is False
    assert b.notes == ""


def test_patch_merges_and_leaves_omitted_fields_untouched():
    """L3: PATCH is the merge path — only the supplied fields change, the rest of
    the declared boundary stands."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    _policy(dep, allowed_regions=["us"], training_allowed=True,
            third_party_sharing_allowed=True, notes="keep me")

    factory = APIRequestFactory()
    patch_view = DeploymentViewSet.as_view({"patch": "data_boundary"})
    req = factory.patch(
        f"/api/assurance/deployments/{dep.uuid}/data-boundary/",
        {"allowed_regions": ["eu"]}, format="json",
    )
    force_authenticate(req, user=admin)
    assert patch_view(req, uuid=str(dep.uuid)).status_code == 200

    b = DataBoundary.objects.get(deployment=dep)
    assert b.allowed_regions == ["eu"]              # changed
    assert b.training_allowed is True               # preserved
    assert b.third_party_sharing_allowed is True    # preserved
    assert b.notes == "keep me"                     # preserved


def test_patch_boundary_is_admin_only():
    """PATCH mutates the record, so it is gated exactly like PUT."""
    admin = _user("boss", role=User.Roles.ADMIN)
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=admin)

    factory = APIRequestFactory()
    patch_view = DeploymentViewSet.as_view({"patch": "data_boundary"})
    req = factory.patch(
        f"/api/assurance/deployments/{dep.uuid}/data-boundary/",
        {"training_allowed": True}, format="json",
    )
    force_authenticate(req, user=analyst)
    assert patch_view(req, uuid=str(dep.uuid)).status_code == 403
    assert not DataBoundary.objects.filter(deployment=dep).exists()


# --- O1: an ignorance marker is an unknown, never a pass or a violation ------


def test_ignorance_marker_subprocessors_is_unknown_not_a_violation():
    """O1: subprocessors declared "n/a" names no posture — an undeclared sharing
    stance is an unknown, not a third-party-sharing violation."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Vendor", region="eu-west-1", trains_on_data="No", subprocessors="n/a")
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["eu-west-1"])  # sharing forbidden by default

    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "unknown"
    assert flow["violations"] == []
    assert any("sharing" in u for u in flow["unknowns"])


def test_ignorance_marker_training_is_unknown_not_silently_benign():
    """O1: training declared "tbd" is an unknown, not a silent pass."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Vendor", region="eu-west-1", trains_on_data="tbd", subprocessors="none")
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["eu-west-1"])

    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "unknown"
    assert flow["violations"] == []
    assert any("training" in u for u in flow["unknowns"])


def test_ignorance_marker_region_is_unknown_not_a_violation():
    """O1: region declared "unknown" is an unknown, not an out-of-boundary violation."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Vendor", region="unknown", trains_on_data="No", subprocessors="none")
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["eu-west-1"])

    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "unknown"
    assert flow["violations"] == []
    assert any("region" in u for u in flow["unknowns"])


def test_named_subprocessor_still_flags_after_the_ignorance_guard():
    """The ignorance guard must not weaken a real sharing declaration: a named
    vendor is still a third-party-sharing violation."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider(
        "Vendor", region="eu-west-1", trains_on_data="No", subprocessors="Stripe, Twilio"
    )
    _asset(dep, provider=p, name="m")
    _policy(dep, allowed_regions=["eu-west-1"])

    flow = boundary.assess_boundary(dep)["flows"][0]
    assert flow["status"] == "violation"
    assert any("subprocessor" in v for v in flow["violations"])
