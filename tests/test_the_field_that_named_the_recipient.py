"""The packet redacted the customer's hostname out of one field and shipped it in another.

`assurance/vendor_packet.py` promises, in its own docstring, that the packet
"leaves the customer's control, so it carries no deployment name, no tenant, no
internal hostname, no asset identifier, no owner." Every part of the payload
built from a model field ran through `_redact` — except `_implicated_provider`,
which is the field naming who the packet is ADDRESSED to.

That mattered because of what fills it. `assurance/assets.py` builds a Provider
from the customer's declared target with ``provider_name = _host(base_url)``, so
for a self-hosted or private gateway ``Provider.name`` **is** the customer's
internal hostname. One observed payload:

    title           : 'tool call reached [redacted]'
    implicated.name : 'llm-gw.acmebank.corp'
    implicated.regn : '10.20.30.40 / us-east-1'

The same host, redacted out of the title and handed over two fields above it.
`_LEAK_PATTERNS` already matched it — which is how the title got redacted — so
this was never a gap in what the module knows how to catch. It was a builder
branch that did not ask.

AND THE GUARD THAT WOULD HAVE CAUGHT IT DID NOT EXIST. Three places said it
did: the module docstring ("a guard enumerates the rendered payload for anything
that looks like a leak rather than trusting the construction"), the comment above
`_LEAK_PATTERNS` ("enumerated so the guard can walk the rendered payload rather
than trusting that each builder branch remembered to redact"), and the docstring
of the test file that added the routes. There was no such guard in the module.
The only enumeration lived in tests, and it injected leaky strings through the
title, the impact, the deployment name and the asset name — never through the
provider — which is exactly why forty-one tests passed over this.

So the guard is real now, and these tests are about the two halves that make it
worth having: it cannot leak, and it cannot run silently.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import Asset, Deployment, Finding, Provider
from assurance.vendor_packet import _LEAK_PATTERNS, build_vendor_packet
from assurance.views import DeploymentViewSet, FindingViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(
        username=f"{name}-{User.objects.count()}",
        password="x",
        role=role or User.Roles.ANALYST,
    )


def _deployment(owner=None, name="checkout-assistant"):
    return Deployment.objects.create(name=name, owner=owner or _user("owner"))


def _finding(dep, *, provider_name=None, region="", title="Requests bypass the tenant header"):
    # Provider is unique on (name, kind), so every call needs its own vendor
    # unless the test names one deliberately.
    provider = Provider.objects.create(
        name=provider_name or f"acme-llm-{Provider.objects.count()}",
        kind=Provider.Kind.MODEL_PROVIDER,
        region=region,
    )
    # Asset is unique on (deployment, kind, identifier) too.
    asset = Asset.objects.create(
        deployment=dep,
        kind=Asset.Kind.GATEWAY,
        name="gateway",
        identifier=f"gateway-{Asset.objects.count()}",
        provider=provider,
    )
    return Finding.objects.create(
        deployment=dep,
        asset=asset,
        fingerprint=f"fp-{Finding.objects.count()}",
        finding_type="tenant_isolation",
        title=title,
        raw={},
    )


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


# ---------------------------------------------------------------------------
# The leak
# ---------------------------------------------------------------------------


def test_the_provider_name_is_redacted_like_every_other_model_field():
    """The exact payload observed before the fix, asserted field by field."""
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    finding = _finding(
        dep,
        provider_name="llm-gw.acmebank.corp",
        region="10.20.30.40 / us-east-1",
        title="tool call reached https://llm-gw.acmebank.corp/v1/chat",
    )

    packet = build_vendor_packet(finding)

    assert "acmebank.corp" not in packet["implicated_component"]["name"]
    assert "10.20.30.40" not in packet["implicated_component"]["region"]
    # The control that makes the two assertions above mean something: the title
    # was ALREADY redacted before this change, so a test that only checked the
    # title would have passed throughout.
    assert "acmebank.corp" not in packet["title"]
    # And the part a vendor legitimately needs survives. A redaction that removed
    # the whole field would pass the assertions above and destroy the packet.
    assert "us-east-1" in packet["implicated_component"]["region"]
    # THE BUILDER did this, not the guard, and the distinction is the reason this
    # line is here. With the guard in place, deleting `_redact` from
    # `_implicated_provider` leaves the payload clean anyway -- the guard catches
    # it downstream -- so every assertion above passes with the original bug
    # restored. That is defence in depth working, and it is also how a backstop
    # quietly becomes the primary mechanism.
    #
    # A guard that fires in normal operation is a guard doing a builder's job, and
    # the next forgotten field will be caught by nothing, because the signal that
    # something is wrong is already on. So: on a well-built packet the guard must
    # find NOTHING, whatever the input looks like.
    assert packet["redaction"]["guard_caught"] == [], (
        "the guard cleaned up after the builder; the builder must redact its own "
        "fields, and the guard must stay a backstop that never fires"
    )


def test_the_vendor_still_learns_which_vendor_they_are():
    """The redaction is shape-based, not blanket. A real vendor name carries no
    leak shape and must arrive intact, or the packet cannot be addressed."""
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    finding = _finding(dep, provider_name="acme-llm", region="us-east-1")

    packet = build_vendor_packet(finding)
    assert packet["implicated_component"]["name"] == "acme-llm"
    assert packet["implicated_component"]["region"] == "us-east-1"
    assert packet["redaction"]["guard_clean"] is True


def test_no_leak_pattern_survives_anywhere_in_the_rendered_payload():
    """The property the module claims, over the WHOLE payload rather than over the
    fields somebody remembered.

    Every string reachable in the packet is re-checked against every leak
    pattern. This is the test that would have failed on the provider name, and it
    fails on the next forgotten field too, whichever one that turns out to be.
    """
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    finding = _finding(
        dep,
        provider_name="llm-gw.acmebank.corp",
        region="10.20.30.40",
        title="auth bypass, authorization: Bearer sk-live-AAAABBBB at https://gw.acmebank.corp",
    )

    packet = build_vendor_packet(finding)

    exempt = {"finding_reference", "built_at", "packet_version", "scope_note", "status"}

    def walk(value, path=""):
        leaks = []
        if isinstance(value, str):
            for pattern in _LEAK_PATTERNS:
                if pattern.search(value):
                    leaks.append((path, pattern.pattern, value))
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in exempt:
                    continue
                leaks += walk(item, f"{path}.{key}" if path else key)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                leaks += walk(item, f"{path}[{index}]")
        return leaks

    assert walk(packet) == []


# ---------------------------------------------------------------------------
# The guard, and the half that keeps it from becoming decorative
# ---------------------------------------------------------------------------


def test_the_guard_catches_a_builder_branch_that_stops_redacting():
    """The guard's own test, and it has to be a real one.

    A guard proven only by "the payload is clean" is indistinguishable from no
    guard at all -- the builders already redact, so that assertion passes either
    way. So this removes the redaction from the builder and asserts the guard
    catches what gets through, which is the only circumstance the guard exists
    for.
    """
    from assurance import vendor_packet as vp

    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    finding = _finding(dep, provider_name="llm-gw.acmebank.corp")

    original = vp._implicated_provider

    def unredacted(f):
        out = original(f)
        if out is not None:
            # Exactly the bug this file is about, reintroduced on purpose.
            out["name"] = f.asset.provider.name
        return out

    vp._implicated_provider = unredacted
    try:
        packet = build_vendor_packet(finding)
    finally:
        vp._implicated_provider = original

    # It cannot leak: the guard cleaned it even though the builder did not.
    assert "acmebank.corp" not in packet["implicated_component"]["name"]
    # And it cannot run silently: the path it caught is named.
    assert packet["redaction"]["guard_clean"] is False
    assert "implicated_component.name" in packet["redaction"]["guard_caught"]


def test_a_clean_packet_says_the_guard_found_nothing_rather_than_omitting_it():
    """An absent key reads as "nothing to report" exactly like an empty list does,
    and this module exists to keep that distinction. `guard_caught: []` is a
    measurement; a missing `redaction` block is a silence."""
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    packet = build_vendor_packet(_finding(dep))

    assert packet["redaction"]["guard_caught"] == []
    assert packet["redaction"]["guard_clean"] is True


def test_the_guard_leaves_the_reference_digest_alone():
    """The salted digest is high-entropy and can match a credential shape by
    accident. Redacting it would remove the one identifier the vendor genuinely
    needs, to protect a value that is already a one-way function of it."""
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    finding = _finding(dep)

    packet = build_vendor_packet(finding)
    assert packet["finding_reference"]
    assert packet["finding_reference"] != "[redacted]"
    assert packet["finding_reference"] == build_vendor_packet(finding)["finding_reference"]


# ---------------------------------------------------------------------------
# The scoping nobody was testing
# ---------------------------------------------------------------------------


def test_the_packet_route_cannot_widen_what_a_caller_may_see():
    """The gap this file closes second, and it was mine.

    The route that ADDED the packet tested the candidates route's scoping and not
    the packet route's. Replacing the packet route's scoped lookup
    (`.get(pk=self.get_object().pk)`) with an unscoped one (`.get(uuid=uuid)`)
    left all forty-one tests passing -- a cross-tenant read of another customer's
    finding, shipping green.

    A VIEWER, not an analyst: `_is_privileged` deliberately admits analysts to the
    whole assurance read model, so an analyst reading another deployment is the
    design and not a leak.
    """
    outsider = _user("viewer-outsider", role=User.Roles.VIEWER)
    dep = _deployment(owner=_user("theirs"))
    finding = _finding(dep)

    assert _get_packet(finding, outsider).status_code == 404

    # Two controls, so this cannot pass on a route that refuses everyone.
    own_viewer = _user("viewer-owner", role=User.Roles.VIEWER)
    own = _deployment(owner=own_viewer, name="their-own")
    assert _get_packet(_finding(own), own_viewer).status_code == 200
    assert _get_packet(finding, _user("ana")).status_code == 200


# ---------------------------------------------------------------------------
# The candidates payload: bounded, and its shape pinned
# ---------------------------------------------------------------------------


def test_the_candidates_payload_carries_exactly_these_fields():
    """The candidates list is hand-written in the view, bypassing the module's
    redaction entirely, and nothing pinned WHICH fields it carries.

    Adding `deployment`, `component` (the asset identifier, which `assets.py`
    fills with endpoint URLs) and `component_name` to it left all forty-one tests
    passing. Those are the customer's internals, on the route that enumerates
    them. An exact field set is the only assertion that catches an addition.
    """
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    _finding(dep)

    resp = _get_candidates(dep, analyst)
    assert resp.status_code == 200
    assert set(resp.data["eligible"][0]) == {
        "uuid",
        "title",
        "severity",
        "provider",
        "provider_kind",
        "component_kind",
    }


def test_the_eligible_list_is_bounded_and_says_when_it_truncated():
    """`config/settings.py` gives the reason this matters in its own words: the
    pagination default exists because "List endpoints returned every row. A
    hundred and fifty scans came back in one response, and nothing bounded it." A
    custom @action returning a bare Response opts out of that silently.

    The counts stay whole, which is the only way bounding is honest: a caller
    reading `eligible_count` gets how many are eligible, not how many arrived.
    """
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    size = DeploymentViewSet.CANDIDATE_PAGE_SIZE
    for _ in range(size + 7):
        _finding(dep)

    resp = _get_candidates(dep, analyst)
    assert len(resp.data["eligible"]) == size
    assert resp.data["eligible_returned"] == size
    assert resp.data["eligible_truncated"] is True
    assert resp.data["eligible_count"] == size + 7
    assert resp.data["total"] == size + 7


def test_a_short_list_is_not_reported_as_truncated():
    """The control. `eligible_truncated: True` for every response would satisfy
    the test above and tell every caller its complete list was partial."""
    analyst = _user("ana")
    dep = _deployment(owner=analyst)
    _finding(dep)
    _finding(dep)

    resp = _get_candidates(dep, analyst)
    assert resp.data["eligible_truncated"] is False
    assert resp.data["eligible_returned"] == 2
    assert resp.data["eligible_count"] == 2


# ---------------------------------------------------------------------------
# The sibling route with the identical gap
# ---------------------------------------------------------------------------


def test_the_incident_pack_route_cannot_widen_what_a_caller_may_see():
    """Found by pointing the same mutation at the route next door.

    `incident_pack` and `vendor_packet` share the same scoped-lookup block, line
    for line. Replacing `incident_pack`'s with an unscoped `.get(uuid=uuid)` left
    all fifty-one tests passing, exactly as `vendor_packet`'s did before the test
    above existed.

    The incident pack is the wider exposure of the two: it reconstructs the
    incident's identity, context, surface, evidence, receipt, blast radius and
    decision from the stored graph. This predates the vendor packet work and is
    fixed here because it is one test in the file that proves the shape, and
    leaving a known unscoped-read gap open next to the one being closed is not a
    scoping decision, it is an omission.
    """
    view = FindingViewSet.as_view({"get": "incident_pack"})

    def get_pack(finding, user):
        req = APIRequestFactory().get(
            f"/api/assurance/findings/{finding.uuid}/incident-pack/"
        )
        force_authenticate(req, user=user)
        return view(req, uuid=str(finding.uuid))

    outsider = _user("viewer-outsider-ip", role=User.Roles.VIEWER)
    dep = _deployment(owner=_user("theirs-ip"))
    finding = _finding(dep)

    assert get_pack(finding, outsider).status_code == 404

    # The same two controls: this must not pass on a route that refuses everyone.
    own_viewer = _user("viewer-owner-ip", role=User.Roles.VIEWER)
    own = _deployment(owner=own_viewer, name="their-own-ip")
    assert get_pack(_finding(own), own_viewer).status_code == 200
    assert get_pack(finding, _user("ana-ip")).status_code == 200
