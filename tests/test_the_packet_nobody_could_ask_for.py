"""The vendor-coordination packet had no route, so nothing could ask for one.

`assurance.vendor_packet` is a complete, well-tested module -- seven required
sections, a redaction pass, a leak guard over the rendered payload -- and
`grep` for `build_vendor_packet` outside its own test file returned nothing. No
view, no URL, no serializer, no admin action, no management command. A
capability with no route is a decorative one: the product advertised that it
hands a vendor a coordination packet and there was no way to obtain one.

These tests pin the two routes that open it, and the one case the finding route
REFUSES. The refusal is the interesting half: the module's own rule is that a
packet sent to a vendor who is not involved is worse than no packet, and a
packet naming NO vendor is the degenerate case -- every section renders, so it
reads as finished, addressed to nobody.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import Asset, Deployment, Finding, Provider
from assurance.vendor_packet import REQUIRED_SECTIONS, build_vendor_packet
from assurance.views import DeploymentViewSet, FindingViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst"):
    return User.objects.create_user(
        username=f"{name}-{User.objects.count()}", password="x", role=User.Roles.ANALYST
    )


def _deployment(owner=None, name="checkout-assistant"):
    return Deployment.objects.create(name=name, owner=owner or _user("owner"))


def _asset(dep, provider=None, *, name="gateway"):
    return Asset.objects.create(
        deployment=dep,
        kind=Asset.Kind.GATEWAY,
        name=name,
        identifier=name,
        provider=provider,
    )


def _finding(dep, asset=None, *, fingerprint="fp-1", **kw):
    fields = {
        "deployment": dep,
        "asset": asset,
        "fingerprint": fingerprint,
        "finding_type": "tenant_isolation",
        "title": "Requests bypass the tenant header",
        "raw": {},
    }
    fields.update(kw)
    return Finding.objects.create(**fields)


def _get_packet(finding, user):
    view = FindingViewSet.as_view({"get": "vendor_packet"})
    req = APIRequestFactory().get(f"/api/assurance/findings/{finding.uuid}/vendor-packet/")
    force_authenticate(req, user=user)
    return view(req, uuid=str(finding.uuid))


def _get_candidates(deployment, user):
    view = DeploymentViewSet.as_view({"get": "vendor_packet_candidates"})
    req = APIRequestFactory().get(
        f"/api/assurance/deployments/{deployment.uuid}/vendor-packet-candidates/"
    )
    force_authenticate(req, user=user)
    return view(req, uuid=str(deployment.uuid))


# --- the packet can now be asked for ----------------------------------------


def test_the_packet_is_reachable_and_is_the_module_s_own_packet():
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    provider = Provider.objects.create(
        name="acme-llm", kind=Provider.Kind.MODEL_PROVIDER
    )
    finding = _finding(dep, _asset(dep, provider))

    resp = _get_packet(finding, analyst)

    assert resp.status_code == 200
    # Every required section, which is the module's own contract.
    assert set(resp.data["sections"]) == set(REQUIRED_SECTIONS)
    # Top-level, not a section: the vendor is who the packet is ADDRESSED to.
    assert resp.data["implicated_component"]["name"] == "acme-llm"
    # The route adds no content of its own: identical to the direct build on
    # every key except `built_at`, which is `timezone.now()` and so differs
    # between any two calls. Compared the way `incident.py` compares a reused
    # receipt -- drop the timestamp, keep everything the packet asserts.
    served = dict(resp.data)
    direct = build_vendor_packet(finding)
    assert served.pop("built_at") != direct.pop("built_at"), (
        "built_at is a live timestamp, not a stored one; if these matched the "
        "comparison below would be proving nothing about the rest"
    )
    assert served == direct
    # And the stable identity does NOT move between calls, which is the half a
    # vendor needs to refer to the same thing twice.
    assert resp.data["finding_reference"] == build_vendor_packet(finding)["finding_reference"]


def test_the_packet_route_needs_authentication():
    dep = _deployment()
    finding = _finding(dep, _asset(dep, Provider.objects.create(name="p")))
    view = FindingViewSet.as_view({"get": "vendor_packet"})
    req = APIRequestFactory().get(f"/api/assurance/findings/{finding.uuid}/vendor-packet/")
    resp = view(req, uuid=str(finding.uuid))
    assert resp.status_code in (401, 403)


# --- and refused where there is nobody to send it to ------------------------


def test_a_finding_implicating_no_third_party_is_refused_not_served_empty():
    """The refusal, and why it is not a 200 with a null vendor.

    Without it the route answers 200 with ``implicated_component: null`` and all
    seven sections rendered -- an artifact that reads as a finished packet and
    names nobody to send it to.
    """
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    # An asset with no provider, and a finding with no asset at all: both are
    # findings the packet cannot be about.
    for finding in (
        _finding(dep, _asset(dep, None, name="own-gateway"), fingerprint="fp-a"),
        _finding(dep, None, fingerprint="fp-b"),
    ):
        resp = _get_packet(finding, analyst)
        assert resp.status_code == 409, finding.fingerprint
        assert "implicates no third-party component" in resp.data["detail"]

    # The control, beside it: the same route on the same deployment DOES serve a
    # finding whose asset names a provider. The refusal is about eligibility, not
    # a broken route.
    eligible = _finding(
        dep,
        _asset(dep, Provider.objects.create(name="acme"), name="vendor-gateway"),
        fingerprint="fp-c",
    )
    assert _get_packet(eligible, analyst).status_code == 200


def test_the_null_vendor_packet_really_would_have_rendered_as_finished():
    """Proof the refusal is guarding something, not being defensive for form.

    Called directly, the builder does produce a complete-looking packet for a
    finding with no provider. That is what the route refuses to serve.
    """
    dep = _deployment()
    packet = build_vendor_packet(_finding(dep, _asset(dep, None)))

    assert packet["implicated_component"] is None
    # Every section still renders, and `complete`/`missing_sections` are computed
    # over the sections alone, so nothing in the payload says "addressed to
    # nobody". That is what makes it read as finished.
    assert set(packet["sections"]) == set(REQUIRED_SECTIONS)
    assert "implicated_component" not in packet["missing_sections"]


# --- and a caller can find out which findings are eligible ------------------


def test_the_candidates_route_lists_the_eligible_findings_and_the_total():
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    provider = Provider.objects.create(
        name="acme-llm", kind=Provider.Kind.MODEL_PROVIDER
    )
    eligible = _finding(dep, _asset(dep, provider, name="vendor-gw"), fingerprint="fp-y")
    _finding(dep, _asset(dep, None, name="own-gw"), fingerprint="fp-n")
    _finding(dep, None, fingerprint="fp-none")

    resp = _get_candidates(dep, analyst)

    assert resp.status_code == 200
    assert [row["uuid"] for row in resp.data["eligible"]] == [str(eligible.uuid)]
    assert resp.data["eligible_count"] == 1
    # The total is beside it: "one of three" and "one of one" are different
    # situations and a bare list of one cannot tell them apart.
    assert resp.data["total"] == 3
    assert resp.data["eligible"][0]["provider"] == "acme-llm"


def test_the_list_and_the_refusal_cannot_disagree_about_eligibility():
    """Both routes read the same function, and this asserts it end to end.

    Two ways of deciding who is eligible is how a caller ends up with a 409 on a
    finding the list offered it.
    """
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    provider = Provider.objects.create(name="acme-llm")
    findings = [
        _finding(dep, _asset(dep, provider, name="a"), fingerprint="f1"),
        _finding(dep, _asset(dep, None, name="b"), fingerprint="f2"),
        _finding(dep, _asset(dep, provider, name="c"), fingerprint="f3"),
        _finding(dep, None, fingerprint="f4"),
    ]
    listed = {row["uuid"] for row in _get_candidates(dep, analyst).data["eligible"]}

    for finding in findings:
        served = _get_packet(finding, analyst).status_code == 200
        assert served is (str(finding.uuid) in listed), finding.fingerprint

    # The control: this is not vacuous in either direction.
    assert 0 < len(listed) < len(findings)


def test_the_candidates_route_needs_authentication():
    dep = _deployment()
    view = DeploymentViewSet.as_view({"get": "vendor_packet_candidates"})
    req = APIRequestFactory().get(
        f"/api/assurance/deployments/{dep.uuid}/vendor-packet-candidates/"
    )
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code in (401, 403)


def test_the_candidates_route_cannot_widen_what_a_caller_may_see():
    """Scoped exactly like the deployment list, like every other read here.

    Tested with a VIEWER rather than an analyst: `_is_privileged` deliberately
    admits admins and analysts to the whole assurance graph, so an analyst seeing
    somebody else's deployment is the read model working, not a leak. A viewer is
    the role the queryset actually narrows for, and narrowing is the claim.
    """
    outsider = User.objects.create_user(
        username="viewer-outsider", password="x", role=User.Roles.VIEWER
    )
    theirs = _user("theirs")
    dep = _deployment(owner=theirs)
    _finding(dep, _asset(dep, Provider.objects.create(name="acme")))

    assert _get_candidates(dep, outsider).status_code == 404

    # Two controls: its owner can see it, and so can an analyst, which is what
    # the read model intends. Asserting only the 404 would pass on a route that
    # refuses everyone.
    owner_view = User.objects.create_user(
        username="viewer-owner", password="x", role=User.Roles.VIEWER
    )
    own = _deployment(owner=owner_view, name="theirs-own")
    _finding(own, _asset(own, Provider.objects.create(name="beta")))
    assert _get_candidates(own, owner_view).status_code == 200
    assert _get_candidates(dep, _user("ana")).status_code == 200
