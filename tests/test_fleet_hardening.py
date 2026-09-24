"""
Regressions from an adversarial fleet run against the hardened branch.

Each test here corresponds to something the fleet demonstrated: a guard that
could be walked around, an input shape that turned a 400 into a 500, or two
correct-looking pieces that compose into a wrong answer. The comments say what
was observed, not what was feared.
"""

import socket
import uuid
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from pentest import views
from pentest.models import Engagement, PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
TARGET = "https://app.client.example/login"


@pytest.fixture()
def factory():
    return APIRequestFactory()


@pytest.fixture()
def analyst():
    return User.objects.create_user(username="fleet", password="x", role=User.Roles.ANALYST)


@pytest.fixture()
def engagement(analyst):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=analyst,
        name="Client Q3",
        status="running",
        scope_hosts=["client.example"],
        testing_window_start=now - timedelta(hours=1),
        testing_window_end=now + timedelta(hours=1),
    )


def post(factory, user, view, body, path="/api/pentest/scan/"):
    request = factory.post(path, body, format="json")
    force_authenticate(request, user=user)
    return view(request)


# ---------------------------------------------------------------------------
# Scope entries must not be able to authorise the whole internet
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry",
    [
        # lstrip("*.") strips those characters rather than that prefix, so each
        # of these left a bare public suffix behind as a matchable one.
        ".com", "*.com", "com", "*.co.uk", "co.uk", "", "   ", "*", "*.",
    ],
)
def test_a_scope_entry_that_is_a_bare_or_public_suffix_authorises_nothing(entry):
    engagement = Engagement(scope_hosts=[entry])

    assert not engagement.covers("victim.com")
    assert not engagement.covers("bank.co.uk")


def test_a_wildcard_entry_still_authorises_its_own_subdomains():
    engagement = Engagement(scope_hosts=["*.client.example"])

    assert engagement.covers("api.client.example")
    assert engagement.covers("client.example")
    assert not engagement.covers("client.example.evil.test")


@pytest.mark.parametrize("entry", [None, 5, True, {"host": "client.example"}, ["client.example"]])
def test_a_non_string_scope_entry_is_ignored_rather_than_stringified(entry):
    # str(None) is "none", which was a matchable hostname.
    engagement = Engagement(scope_hosts=[entry])

    assert not engagement.covers("none")
    assert not engagement.covers("client.example")


@pytest.mark.parametrize("stored", [5, "client.example", {"a": 1}, True, None])
def test_a_scope_stored_as_something_other_than_a_list_authorises_nothing(stored):
    """It used to raise inside the loop, so authorisation answered 500."""
    engagement = Engagement(scope_hosts=stored)

    assert engagement.covers("client.example") is False


def test_the_serializer_will_not_store_a_scope_that_is_not_a_list_of_hosts(analyst):
    from pentest.serializers import EngagementSerializer

    serializer = EngagementSerializer(data={"name": "x", "scope_hosts": 5})
    assert not serializer.is_valid()
    assert "scope_hosts" in serializer.errors


def test_created_by_cannot_be_claimed_through_the_serializer(analyst):
    from pentest.serializers import EngagementSerializer

    other = User.objects.create_user(username="victim", password="x", role=User.Roles.ANALYST)
    request = mock.Mock(user=analyst)
    serializer = EngagementSerializer(
        data={"name": "x", "created_by": other.pk}, context={"request": request}
    )
    assert serializer.is_valid(), serializer.errors
    assert serializer.save().created_by == analyst


# ---------------------------------------------------------------------------
# Internal addresses written the long way round
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::7f00:1",      # NAT64 loopback
        "64:ff9b::a00:1",       # NAT64 10.0.0.1
        "64:ff9b::a9fe:a9fe",   # NAT64 cloud metadata
        "::ffff:0:7f00:1",      # IPv4-translated loopback
        "224.0.0.1",            # multicast
        "ff02::1",              # multicast
        "fec0::1",              # site-local
        "192.88.99.1",          # 6to4 relay anycast
        "2002:7f00:0001::",     # 6to4 wrapping 127.0.0.1
    ],
)
def test_an_internal_address_in_a_translated_form_is_still_refused(address):
    """
    Each of these was checked in its outer form, found not to be private in
    that form, and allowed. They are all ways of writing an address inside the
    perimeter.
    """
    resolved = [(socket.AF_INET6, None, None, "", (address, 0))]
    with mock.patch("pentest.views.socket.getaddrinfo", return_value=resolved):
        reason = views.target_is_out_of_bounds("https://looks-fine.example/")

    assert reason, f"{address} was accepted as a scan target"


@pytest.mark.parametrize(
    "error", [socket.timeout("timed out"), OSError("net down"), socket.herror("no host")]
)
def test_a_resolver_failure_refuses_the_target_instead_of_raising(error):
    """Only gaierror was caught, so the other three became a 500."""
    with mock.patch("pentest.views.socket.getaddrinfo", side_effect=error):
        assert views.target_is_out_of_bounds("https://client.example/")


def test_a_host_that_resolves_to_nothing_is_refused():
    """The loop had nothing to iterate, so it fell through and allowed it."""
    with mock.patch("pentest.views.socket.getaddrinfo", return_value=[]):
        assert views.target_is_out_of_bounds("https://client.example/")


@pytest.mark.parametrize("url", [["https://x.example/"], {"u": 1}, 5, True, b"https://x.example/"])
def test_a_target_that_is_not_a_string_is_refused_rather_than_raising(url):
    assert views.target_is_out_of_bounds(url)


# ---------------------------------------------------------------------------
# Malformed input is a 400, never a 500
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", [[], [{"url": "https://client.example/"}], "hello", 12345, True])
def test_a_body_that_is_not_an_object_is_refused(factory, analyst, body):
    """request.data.get was called unconditionally, so each of these was a 500."""
    response = post(factory, analyst, views.run_pentest_scan, body)

    assert response.status_code == 400


@pytest.mark.parametrize("attacks", [[["x"]], [None], [5], [{"a": 1}]])
def test_a_malformed_attack_list_is_refused(factory, analyst, attacks):
    """An unhashable entry raised in the membership test; None raised in the join."""
    response = post(
        factory,
        analyst,
        views.run_llm_pentest_scan,
        {
            "base_url": "https://client.example/v1/chat/completions",
            "adapter": "openai_style",
            "attacks": attacks,
            "consent": True,
        },
        path="/api/pentest/llm-scan/",
    )

    assert response.status_code == 400


@pytest.mark.parametrize("adapter", [["generic"], 5, {"a": 1}])
def test_an_adapter_that_is_not_a_string_is_refused(factory, analyst, adapter):
    response = post(
        factory,
        analyst,
        views.run_llm_pentest_scan,
        {
            "base_url": "https://client.example/v1/chat/completions",
            "adapter": adapter,
            "consent": True,
        },
        path="/api/pentest/llm-scan/",
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "recipient", ["not-an-address", ["a@b.example"], "a@b.example\nBcc: x@y.z", "a" * 300]
)
def test_a_recipient_that_is_not_an_address_is_refused(factory, analyst, recipient):
    response = post(
        factory,
        analyst,
        views.run_pentest_scan,
        {"url": TARGET, "consent": True, "recipient_email": recipient},
    )

    assert response.status_code == 400


def test_the_engagement_plan_endpoint_answers(factory, analyst, engagement):
    """It read engagement.kind, which is not a field, so it was a 500 always."""
    request = factory.post(f"/api/pentest/engagements/{engagement.pk}/plan/")
    force_authenticate(request, user=analyst)
    response = views.engagement_plan(request, engagement_id=engagement.pk)

    assert response.status_code == 200
    assert response.data["engagement_id"] == engagement.pk


# ---------------------------------------------------------------------------
# Engagements carry the authority, so they need the same ownership rule
# ---------------------------------------------------------------------------


@pytest.fixture()
def stranger():
    return User.objects.create_user(username="stranger", password="x", role=User.Roles.ANALYST)


def test_another_analyst_cannot_read_or_rewrite_an_engagement(factory, engagement, stranger):
    """
    The engagement is what authorises a scan. One PATCH by any analyst
    rewrote another tenant's scope, and a DELETE removed the record of what
    had been authorised.
    """
    for method, view_args in (("get", {}), ("delete", {})):
        request = getattr(factory, method)(f"/api/pentest/engagements/{engagement.pk}/")
        force_authenticate(request, user=stranger)
        assert views.engagement_detail(request, engagement_id=engagement.pk).status_code == 404

    request = factory.patch(
        f"/api/pentest/engagements/{engagement.pk}/",
        {"scope_hosts": ["victim.example"]},
        format="json",
    )
    force_authenticate(request, user=stranger)
    assert views.engagement_detail(request, engagement_id=engagement.pk).status_code == 404

    engagement.refresh_from_db()
    assert engagement.scope_hosts == ["client.example"]
    assert Engagement.objects.filter(pk=engagement.pk).exists()


def test_an_engagement_list_shows_only_the_callers_own(factory, engagement, stranger):
    request = factory.get("/api/pentest/engagements/")
    force_authenticate(request, user=stranger)

    assert views.engagements_view(request).data == []


# ---------------------------------------------------------------------------
# A scan leaves a record, and a report means the scan happened
# ---------------------------------------------------------------------------


def scan_through(factory, analyst, engagement, engine, url=TARGET):
    request = factory.post(
        "/api/pentest/scan/",
        {"url": url, "consent": True, "engagement_id": engagement.pk},
        format="json",
    )
    force_authenticate(request, user=analyst)
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as client, \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"):
        client.from_settings.return_value = engine
        return views.run_pentest_scan(request)


def test_an_engine_timeout_still_leaves_a_record_of_the_attempt(factory, analyst, engagement):
    """
    The row was created only after the engine answered. A read timeout — which
    the sixty second default makes the ordinary case for a slow target — meant
    the engine ran live-fire tests against a customer and the platform kept no
    record of who authorised it.
    """
    from ai_engine.services.cyberengine_client import ENGINE_UNREACHABLE, EngineError

    engine = mock.Mock()
    engine.run_scan.side_effect = EngineError("Read timed out", kind=ENGINE_UNREACHABLE)

    response = scan_through(factory, analyst, engagement, engine)

    assert response.status_code == 502
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_FAILED
    assert scan.engagement == engagement
    assert "Read timed out" in scan.error_message


@pytest.mark.parametrize("state", [PentestScan.STATUS_FAILED, PentestScan.STATUS_PENDING])
def test_a_scan_that_did_not_complete_has_no_report(factory, analyst, state):
    """
    Neither reporting endpoint looked at the status, so a scan the engine
    refused could still be downloaded as a "PENETRATION TEST REPORT" and
    mailed to the client.
    """
    scan = PentestScan.objects.create(
        uuid=uuid.uuid4(),
        user=analyst,
        target_url=TARGET,
        consent=True,
        status=state,
        recipient_email="client@client.example",
        engine_response={"results": [{"type": "error", "message": "refused"}]},
    )

    request = factory.get(f"/api/pentest/scans/{scan.uuid}/pdf/")
    force_authenticate(request, user=analyst)
    with mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-") as render:
        assert views.download_scan_pdf(request, scan_id=str(scan.uuid)).status_code == 409
    render.assert_not_called()

    request = factory.post(f"/api/pentest/scans/{scan.uuid}/email/")
    force_authenticate(request, user=analyst)
    with mock.patch("pentest.views.send_pentest_scan_email") as send, \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"):
        assert views.resend_scan_email(request, scan_id=str(scan.uuid)).status_code == 409
    send.assert_not_called()


def test_an_engagement_revoked_mid_scan_produces_no_report(factory, analyst, engagement):
    """
    Authorisation was checked once, before an engine call that can take a
    minute. An engagement cancelled during it still produced a finished scan
    and an official report under an authority that no longer existed.
    """
    engine = mock.Mock()

    def run_scan(_url, **_kwargs):
        Engagement.objects.filter(pk=engagement.pk).update(status="cancelled")
        return {"results": [{"type": "info"}]}

    engine.run_scan.side_effect = run_scan

    response = scan_through(factory, analyst, engagement, engine)

    assert response.status_code == 403
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_FAILED


def test_a_report_does_not_count_the_engines_own_refusal_as_a_finding(analyst):
    """
    render_scan_pdf_bytes counted internal findings, so a refused scan
    rendered as "identified 1 finding(s)".
    """
    from pentest.utils import render_scan_pdf_bytes

    scan = PentestScan.objects.create(
        uuid=uuid.uuid4(),
        user=analyst,
        target_url=TARGET,
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={
            "results": [
                {"type": "error", "message": "refused by egress policy", "internal": True}
            ]
        },
    )

    pdf = render_scan_pdf_bytes(scan)
    assert pdf.startswith(b"%PDF-")


@pytest.mark.parametrize("stored", ["a string", ["a", "list"], 5])
def test_a_report_for_a_malformed_engine_response_does_not_raise(analyst, stored):
    from pentest.utils import render_scan_pdf_bytes

    scan = PentestScan.objects.create(
        uuid=uuid.uuid4(), user=analyst, target_url=TARGET, consent=True,
        status=PentestScan.STATUS_COMPLETED, engine_response=stored,
    )

    assert render_scan_pdf_bytes(scan).startswith(b"%PDF-")


def test_a_severity_of_the_wrong_type_does_not_raise(analyst):
    from pentest.utils import render_scan_pdf_bytes

    scan = PentestScan.objects.create(
        uuid=uuid.uuid4(), user=analyst, target_url=TARGET, consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"results": [{"type": "x", "severity": {"nested": 1}}]},
    )

    assert render_scan_pdf_bytes(scan).startswith(b"%PDF-")


def test_saving_the_report_does_not_write_back_a_stale_copy_of_the_row(analyst):
    """
    FieldFile.save defaults to writing the whole row from the in-memory copy,
    so it reverted every column that had changed since the object was loaded:
    a scan marked failed came back as completed.
    """
    from django.core.files.storage import default_storage
    from pentest.utils import save_pdf_to_scan

    scan = PentestScan.objects.create(
        uuid=uuid.uuid4(), user=analyst, target_url=TARGET, consent=True,
        status=PentestScan.STATUS_COMPLETED,
    )
    stale = PentestScan.objects.get(pk=scan.pk)

    scan.mark_failed("engine timeout")
    scan.email_sent = False
    scan.save(update_fields=["email_sent"])

    save_pdf_to_scan(stale, b"%PDF-")

    scan.refresh_from_db()
    try:
        assert scan.status == PentestScan.STATUS_FAILED
        assert scan.error_message == "engine timeout"
        assert scan.pdf_file
    finally:
        if scan.pdf_file:
            default_storage.delete(scan.pdf_file.name)
