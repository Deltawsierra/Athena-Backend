"""Phase 2 item 10 — the vendor-coordination packet.

The roadmap's ask, and every clause in it is a required section:

> Define a vendor-coordination evidence packet, distinct from the customer-facing
> receipt. When a finding implicates a third-party component, package: affected
> version, a minimal reproducer, sanitized request IDs, the observed effect,
> explicit collection limitations, a proposed containment step, and the exact
> unanswered question for the vendor — a narrower, more mechanical artifact than
> the full evidence receipt, built for handoff to someone with no deployment
> context.

"Someone with no deployment context" is the constraint the tests here are built
around, because it cuts both ways: they cannot fill in what we leave out, and
they are not entitled to the customer's internals. So a missing section is
rendered as an explicit "not provided, because ..." rather than dropped — silence
in the limitations section claims we saw everything — and the customer's
identifiers never leave in the payload.

And three things the packet must never become, each tested: a verdict on the
vendor's code, a fix disguised as a containment step, and a reproducer nobody ran.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance.models import (
    Asset,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    Provider,
)
from assurance.vendor_packet import (
    NOT_PROVIDED,
    PACKET_VERSION,
    REQUIRED_SECTIONS,
    build_vendor_packet,
    packet_candidates,
)

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst"):
    return User.objects.create_user(
        username=f"{name}-{User.objects.count()}", password="x", role=User.Roles.ANALYST
    )


def _deployment(name="checkout-assistant"):
    return Deployment.objects.create(name=name, owner=_user("owner"))


def _provider(name="acme-llm"):
    return Provider.objects.create(name=name, kind=Provider.Kind.MODEL_PROVIDER)


def _asset(dep, provider=None, *, name="gateway", metadata=None):
    return Asset.objects.create(
        deployment=dep,
        kind=Asset.Kind.GATEWAY,
        name=name,
        identifier=name,
        provider=provider,
        metadata=metadata or {},
    )


def _finding(
    dep, asset=None, *, raw=None, title="Requests bypass the tenant header", **kw
):
    fields = {
        "deployment": dep,
        "asset": asset,
        "fingerprint": "fp-1",
        "finding_type": "tenant_isolation",
        "title": title,
        "raw": raw or {},
    }
    fields.update(kw)
    return Finding.objects.create(**fields)


def _full_raw():
    return {
        "version": "4.2.1",
        "reproducer": "POST a request with no tenant header; the response carries another tenant's id.",
        "reproduced": True,
        "request_id": "3f2a91c4-1b77-4e02-9a55-8cf1b2d3e4f5",
        "proposed_containment": "Reject requests with no tenant header at the edge.",
        "open_question": "Does the gateway fall back to a default tenant when the header is absent?",
        "collection_limitations": ["We could not observe the gateway's routing table."],
    }


# ---------------------------------------------------------------------------
# All seven sections, always present
# ---------------------------------------------------------------------------


def test_every_required_section_is_present_on_a_full_packet():
    dep = _deployment()
    finding = _finding(
        dep, _asset(dep, _provider()), raw=_full_raw(), impact="Cross-tenant read"
    )

    packet = build_vendor_packet(finding)

    assert set(REQUIRED_SECTIONS) <= set(packet["sections"])
    assert packet["complete"] is True
    assert packet["missing_sections"] == []
    assert packet["packet_version"] == PACKET_VERSION


def test_every_required_section_is_present_even_when_there_is_nothing_behind_it():
    """Enumerate, do not spot-check. A dropped section reads as "nothing to say
    here", and for the limitations section that is a claim we saw everything."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()), title="")

    packet = build_vendor_packet(finding)

    for name in REQUIRED_SECTIONS:
        assert name in packet["sections"], name
        assert "provided" in packet["sections"][name], name


def test_a_missing_section_carries_the_reason_it_is_missing():
    """ "We did not collect this" and "there was nothing to collect" are different
    facts, and a vendor triaging the report has to be able to tell them apart."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()))

    packet = build_vendor_packet(finding)
    version = packet["sections"]["affected_version"]

    assert version["provided"] is False
    assert version["status"] == NOT_PROVIDED
    assert version["reason"]
    assert "not inferred" in version["reason"] or "not recorded" in version["reason"]


def test_an_incomplete_packet_says_so_rather_than_being_refused():
    """An incomplete packet is often exactly what you send first. Blocking on
    completeness would push a reporter into filling sections with guesses, which
    is the failure this artifact exists to avoid."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()))

    packet = build_vendor_packet(finding)

    assert packet["complete"] is False
    assert "affected_version" in packet["missing_sections"]
    assert "open_question" in packet["missing_sections"]


def test_the_limitations_section_is_never_empty():
    """The honest floor holds for every packet this builds: an outside observer
    cannot see the vendor's implementation. A vendor needs that stated before they
    read our observations as claims about their code."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()))

    limitations = build_vendor_packet(finding)["sections"]["collection_limitations"]

    assert limitations["provided"] is True
    assert limitations["limitations"]
    assert any(
        "outside the vendor's system" in line for line in limitations["limitations"]
    )


def test_an_absent_confidence_is_named_as_unquantified_not_low():
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()), confidence=None)

    lines = build_vendor_packet(finding)["sections"]["collection_limitations"][
        "limitations"
    ]

    assert any("unquantified rather than low" in line for line in lines)


def test_having_no_evidence_rows_is_stated_as_a_limitation():
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()))

    lines = build_vendor_packet(finding)["sections"]["collection_limitations"][
        "limitations"
    ]
    assert any("No evidence rows" in line for line in lines)

    Evidence.objects.create(
        finding=finding,
        classification=EvidenceClass.TECHNICALLY_VERIFIED,
        summary="a capture",
    )
    lines = build_vendor_packet(finding)["sections"]["collection_limitations"][
        "limitations"
    ]
    assert not any("No evidence rows" in line for line in lines)


# ---------------------------------------------------------------------------
# Nothing that identifies the customer leaves
# ---------------------------------------------------------------------------


def test_the_packet_carries_no_deployment_or_asset_identity():
    """It leaves the customer's control. The vendor gets the component CLASS, not
    the customer's name for their instance of it."""
    dep = _deployment("acme-corp-checkout-prod")
    asset = _asset(dep, _provider(), name="acme-internal-gateway-01")
    finding = _finding(dep, asset, raw=_full_raw())

    import json

    rendered = json.dumps(build_vendor_packet(finding))

    assert "acme-corp-checkout-prod" not in rendered
    assert "acme-internal-gateway-01" not in rendered
    assert str(dep.uuid) not in rendered
    assert str(asset.uuid) not in rendered


def test_the_raw_request_id_never_leaves_only_a_digest_and_a_shape():
    """The section the roadmap calls "sanitized request IDs", and sanitized has to
    mean something: enough for the vendor to ask about one specific request,
    nothing they could use to enumerate the customer's traffic."""
    dep = _deployment()
    request_id = "3f2a91c4-1b77-4e02-9a55-8cf1b2d3e4f5"
    finding = _finding(dep, _asset(dep, _provider()), raw={"request_id": request_id})

    import json

    packet = build_vendor_packet(finding)
    rendered = json.dumps(packet)
    references = packet["sections"]["request_references"]

    assert request_id not in rendered
    assert references["provided"] is True
    assert references["references"][0]["shape"] == "uuid"
    assert references["references"][0]["reference"] != request_id


def test_the_reference_digest_is_salted_so_it_cannot_be_recomputed_from_a_guess():
    dep = _deployment()
    request_id = "abc123"
    a = _finding(
        dep, _asset(dep, _provider(), name="one"), raw={"request_id": request_id}
    )
    b = _finding(
        dep,
        _asset(dep, _provider("other"), name="two"),
        raw={"request_id": request_id},
        fingerprint="fp-2",
    )

    ref_a = build_vendor_packet(a)["sections"]["request_references"]["references"][0]
    ref_b = build_vendor_packet(b)["sections"]["request_references"]["references"][0]

    assert ref_a["reference"] != ref_b["reference"]


def test_the_same_reference_is_stable_within_one_packet():
    """A vendor has to be able to quote one reference back and mean one request."""
    dep = _deployment()
    finding = _finding(
        dep, _asset(dep, _provider()), raw={"request_ids": ["r-1", "r-2", "r-1"]}
    )

    refs = build_vendor_packet(finding)["sections"]["request_references"]["references"]
    assert len(refs) == 2
    again = build_vendor_packet(finding, salt="fixed")["sections"]["request_references"]
    twice = build_vendor_packet(finding, salt="fixed")["sections"]["request_references"]
    assert again["references"] == twice["references"]


# Each sample is caught by EXACTLY ONE pattern. An earlier version of this table
# used realistic-looking strings that tripped several patterns at once -- an IP
# inside a hostname, a hostname inside a URL -- so deleting any one pattern left
# the others to cover for it and the mutation survived. Overlapping samples test
# the union; isolated ones test each member.
_ISOLATED_LEAKS = [
    (
        "url",
        "Reached https://status.example.com/admin/panel for the check",
        "example.com/admin",
    ),
    (
        "internal hostname",
        "Resolved via db-primary.corp during the call",
        "db-primary.corp",
    ),
    ("ipv4", "Connected to 203.0.113.47 directly", "203.0.113.47"),
    ("aws arn", "Assumed arn:aws:iam::123456789012:role/reader", "arn:aws:iam"),
    ("gcp project", "Wrote to projects/example-42/buckets/logs", "projects/example-42"),
    ("labelled secret", "Called with api_key: AbCdEf123456 attached", "AbCdEf123456"),
    (
        "bearer credential",
        "Header carried Bearer qqqwwweee111 verbatim",
        "qqqwwweee111",
    ),
    ("prefixed token", "Key ghp_ZZZyyy111222 was in the config", "ghp_ZZZyyy111222"),
]


@pytest.mark.parametrize(
    "label,leaky,fragment", _ISOLATED_LEAKS, ids=[x[0] for x in _ISOLATED_LEAKS]
)
def test_internal_identifiers_in_free_text_are_redacted(label, leaky, fragment):
    """Free text is where a leak actually happens: an engineer pastes a real URL
    or a real header into an impact note and it ships to a third party. The guard
    walks the RENDERED payload rather than trusting that each builder branch
    remembered to redact."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()), impact=leaky, title=leaky)

    import json

    rendered = json.dumps(build_vendor_packet(finding))

    assert fragment not in rendered, f"{label}: {fragment} survived"
    assert "[redacted]" in rendered


def test_a_credential_is_redacted_with_its_label_not_just_the_label():
    """A regression guard for a bug in this change. The secret pattern stopped at
    the delimiter, so "authorization: Bearer sk-live-..." had its LABEL redacted
    and its credential shipped to the third party — a redaction that made the
    payload look sanitised while leaking the one thing that mattered."""
    dep = _deployment()
    finding = _finding(
        dep,
        _asset(dep, _provider()),
        impact="Repro used authorization: Bearer sk-live-9f2abc and it worked",
    )

    rendered = build_vendor_packet(finding)["sections"]["observed_effect"]["value"]

    assert "sk-live-9f2abc" not in rendered
    assert "Bearer" not in rendered
    assert "[redacted]" in rendered


def test_a_bare_credential_with_no_label_is_redacted_too():
    dep = _deployment()
    finding = _finding(
        dep, _asset(dep, _provider()), impact="header was Bearer abc123def456"
    )

    rendered = build_vendor_packet(finding)["sections"]["observed_effect"]["value"]
    assert "abc123def456" not in rendered


def test_a_redaction_is_visible_rather_than_a_silent_deletion():
    """A silently dropped identifier leaves the vendor reading a sentence with a
    hole in it and no idea a hole is there."""
    dep = _deployment()
    finding = _finding(
        dep, _asset(dep, _provider()), impact="Leaked via https://x.internal/a"
    )

    effect = build_vendor_packet(finding)["sections"]["observed_effect"]
    assert "[redacted]" in effect["value"]


# ---------------------------------------------------------------------------
# What the packet must never become
# ---------------------------------------------------------------------------


def test_the_packet_carries_no_verdict_on_the_vendors_product():
    """Mythos observes a deployment from outside and cannot see the vendor's
    implementation, so it is in no position to conclude anything about it. The
    receipt concludes; the packet asks."""
    dep = _deployment()
    finding = _finding(
        dep, _asset(dep, _provider()), raw=_full_raw(), severity="critical"
    )

    packet = build_vendor_packet(finding)

    for banned in (
        "verdict",
        "conclusion",
        "pass_fail",
        "assessment",
        "cvss",
        "severity",
    ):
        assert banned not in packet, banned
    assert "asserts nothing about" in packet["scope_note"]
    assert "not an assessment of the vendor's product" in packet["scope_note"]


def test_the_containment_step_says_it_is_not_a_fix():
    """A vendor reading "proposed fix" would reasonably assume the reporter thinks
    it is solved. Same distinction the Contained disposition draws: a control on a
    path is not a removed defect."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()), raw=_full_raw())

    containment = build_vendor_packet(finding)["sections"]["proposed_containment"]

    assert containment["provided"] is True
    assert "does not remove the underlying defect" in containment["note"]
    assert "not proposed as a fix" in containment["note"]


def test_a_reproducer_is_never_presented_as_verified_unless_it_was_run():
    """An unverified reproducer presented as one costs the vendor a day and the
    reporter their credibility, which is the only currency coordinated disclosure
    runs on."""
    dep = _deployment()
    raw = _full_raw()
    raw.pop("reproduced")
    finding = _finding(dep, _asset(dep, _provider()), raw=raw)

    reproducer = build_vendor_packet(finding)["sections"]["minimal_reproducer"]

    assert reproducer["provided"] is True
    assert reproducer["reproduced"] is False
    assert "best reconstruction" in reproducer["reproduced_note"]


def test_a_verified_reproducer_says_so():
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()), raw=_full_raw())
    assert (
        build_vendor_packet(finding)["sections"]["minimal_reproducer"]["reproduced"]
        is True
    )


def test_the_scope_note_is_on_every_packet():
    """A vendor receiving a security report from a security vendor will read it as
    a verdict unless something says otherwise, so the disclaimer is unconditional
    rather than added when the builder judges it needed."""
    dep = _deployment()
    for index, raw in enumerate(({}, _full_raw())):
        finding = _finding(
            dep,
            _asset(dep, _provider(f"vendor-{index}"), name=f"g{index}"),
            raw=raw,
            fingerprint=f"fp{index}",
        )
        packet = build_vendor_packet(finding)
        assert "carries no pass/fail conclusion" in packet["scope_note"]


# ---------------------------------------------------------------------------
# Who a packet is even for
# ---------------------------------------------------------------------------


def test_the_implicated_component_is_read_off_the_graph_not_the_title():
    """A packet sent to a vendor who is not involved spends credibility on a false
    alarm, so membership comes from the asset -> provider edge."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider("acme-llm")), raw=_full_raw())

    component = build_vendor_packet(finding)["implicated_component"]

    assert component["name"] == "acme-llm"
    assert component["kind"] == Provider.Kind.MODEL_PROVIDER


def test_a_finding_with_no_provider_behind_it_implicates_nobody():
    dep = _deployment()
    finding = _finding(dep, _asset(dep, None), raw=_full_raw())
    assert build_vendor_packet(finding)["implicated_component"] is None

    orphan = _finding(dep, None, fingerprint="fp-2")
    assert build_vendor_packet(orphan)["implicated_component"] is None


def test_candidates_are_only_findings_that_implicate_a_third_party():
    dep = _deployment()
    with_provider = _finding(dep, _asset(dep, _provider(), name="gw"), fingerprint="a")
    _finding(dep, _asset(dep, None, name="own-tool"), fingerprint="b")
    _finding(dep, None, fingerprint="c")

    assert [f.pk for f in packet_candidates(dep)] == [with_provider.pk]


def test_a_version_is_read_from_the_record_and_never_guessed():
    """A version we guessed wrong sends a vendor to the wrong branch, which costs
    them more than a blank does."""
    dep = _deployment()
    from_raw = _finding(
        dep, _asset(dep, _provider(), name="a"), raw={"version": "4.2.1"}
    )
    assert (
        build_vendor_packet(from_raw)["sections"]["affected_version"]["value"]
        == "4.2.1"
    )

    from_asset = _finding(
        dep,
        _asset(dep, _provider("p2"), name="b", metadata={"version": "9.9"}),
        fingerprint="fp-2",
    )
    assert (
        build_vendor_packet(from_asset)["sections"]["affected_version"]["value"]
        == "9.9"
    )


def test_the_packet_is_a_pure_read_and_stores_nothing():
    """Computed on read, like the receipt and the vendor posture — no new record,
    no migration, no endpoint under the feature freeze."""
    dep = _deployment()
    finding = _finding(dep, _asset(dep, _provider()), raw=_full_raw())

    before = Finding.objects.count(), Evidence.objects.count(), Asset.objects.count()
    build_vendor_packet(finding)
    build_vendor_packet(finding)
    after = Finding.objects.count(), Evidence.objects.count(), Asset.objects.count()

    assert before == after


def test_the_required_sections_roster_is_the_seven_the_roadmap_names():
    """Pinned so a section cannot be quietly added or dropped from the contract
    without this test saying so."""
    assert set(REQUIRED_SECTIONS) == {
        "affected_version",
        "minimal_reproducer",
        "request_references",
        "observed_effect",
        "collection_limitations",
        "proposed_containment",
        "open_question",
    }
