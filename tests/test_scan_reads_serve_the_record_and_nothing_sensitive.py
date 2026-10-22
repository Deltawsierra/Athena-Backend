"""Scan reads serve the record, and nothing a reader must not have.

GET scan detail built its answer by hand -- uuid, target, status, created_at, the
engine's answer, the error, the run, the Stop -- and the list served four columns.
The record held more that no reader could get: the verdict and its label, the
report's url, the engagement the scan ran under, and now when its end was collected
and whether it was stopped on the engine. ``PentestScanSerializer`` had every one of
those and was used by no view (and served the recipient's address).

Detail and list now serve the record through it: ``verdict``, ``verdict_label``,
``pdf_url``, ``engagement`` (``{id, name, client_name, status}``), ``engine_run_id``,
``stop``, ``collected_at``, ``error_message`` and a ``status`` that may be ``stopped``
-- honestly: no verdict, no report. The list row leaves out ``engine_response`` (the
detail serves it). Nothing sensitive is served: the target's login is withheld, the
recipient's address is not served, and the preflight report (``assurance``) is not
served -- it carries the engine's own words about its errors, which quote the engine's
host, and raw measurements of the deployment's routes. A finding serves ``scan_uuid``
and ``engine_run_id``, the scan it was last observed in; a deployment serves
``engagement_id``.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.models import Deployment, Finding
from pentest.models import WITHHELD_USERINFO, Engagement, PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
RECIPIENT = "ops@client.example"
#: An engine host as a preflight report's error quotes it; it must reach no reader.
INTERNAL_HOST = "cyberengine.internal"
STOPPED = "stopped"
FINDINGS = [
    {"type": "sql_injection", "report_severity": "critical", "confidence": 0.9,
     "tier": "confirmed", "exploit_like": True, "evidence": {"endpoint": "/search"}},
]
PARTIAL = {"results": [
    {"type": "xss", "severity": "high", "message": "Reflected input on /search"},
    {"type": "scan_incomplete", "internal": True, "message": "the remaining scanners did not run"},
]}


def _user(role=None):
    return User.objects.create_user(
        username=f"u-{uuid.uuid4().hex[:10]}", password=None, role=role or User.Roles.ANALYST
    )


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _engagement(user):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=user, name="Client Q3", client_name="Client plc", status="running",
        scope_hosts=["app.client.example"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )


def _completed_scan(user, engagement, password, **over):
    """A completed scan as the record holds one: a login in its target, a recipient, a
    run, a delivered Stop, a collect time, and a preflight report that quotes the
    engine's host in an error."""
    now = timezone.now()
    values = {
        "user": user, "engagement": engagement, "consent": True,
        "target_url": f"https://scanner:{password}@app.client.example/login",
        "status": PentestScan.STATUS_COMPLETED, "verdict": PentestScan.VERDICT_READY_RESTRICTED,
        "engine_response": {"results": [{"type": "xss", "severity": "medium"}]},
        "recipient_email": RECIPIENT, "email_sent": True, "engine_run_id": "run-record-1", "collected_at": now,
        "assurance": {"deployment_id": "athena-engine", "verdict": "unknown",
                      "error": f"Engine unreachable: HTTPConnectionPool(host='{INTERNAL_HOST}', port=8443)"},
        "stop_requested_at": now, "stop_delivered_at": now,
        "stop_detail": "Run run-record-1 had already ended (state 'completed'): nothing was left to stop.",
    }
    values.update(over)
    return PentestScan.objects.create(**values)


SERVED = {
    "uuid", "target_url", "consent", "status", "verdict", "verdict_label", "created_at", "collected_at",
    "engine_run_id", "stop", "pdf_url", "email_sent", "error_message", "engagement",
}


def _nothing_sensitive(response, password):
    text = response.content.decode()
    for secret in (password, f"scanner:{password}", RECIPIENT, INTERNAL_HOST):
        assert secret not in text, f"{secret!r} was served"


# ===========================================================================
# 1. Detail: the record, whole; nothing a reader must not have
# ===========================================================================


def test_scan_detail_serves_the_record_and_withholds_what_a_reader_must_not_have():
    analyst = _user()
    engagement = _engagement(analyst)
    password = uuid.uuid4().hex[:12]
    scan = _completed_scan(analyst, engagement, password)
    client = _client(analyst)

    response = client.get(f"/api/pentest/scans/{scan.uuid}/")

    assert response.status_code == 200, response.content
    body = response.json()
    assert set(body) == SERVED | {"engine_response"}
    assert body["uuid"] == str(scan.uuid)
    assert body["target_url"] == f"https://{WITHHELD_USERINFO}@app.client.example/login"
    assert (body["status"], body["verdict"]) == (PentestScan.STATUS_COMPLETED, PentestScan.VERDICT_READY_RESTRICTED)
    assert body["verdict_label"] == "Ready with restrictions"
    assert body["engagement"] == {
        "id": engagement.pk, "name": "Client Q3", "client_name": "Client plc", "status": "running",
    }
    assert body["engine_run_id"] == "run-record-1"
    assert body["stop"]["state"] == "delivered" and body["stop"]["detail"] == scan.stop_detail
    assert body["collected_at"] is not None and body["created_at"]
    assert body["email_sent"] is True and body["pdf_url"] is None and body["error_message"] is None
    assert body["engine_response"] == scan.engine_response
    _nothing_sensitive(response, password)

    # With a report saved, its url is absolute.
    scan.pdf_file.name = f"pentest_reports/pentest_scan_{scan.uuid}.pdf"
    scan.save(update_fields=["pdf_file"])
    with_report = client.get(f"/api/pentest/scans/{scan.uuid}/").json()
    assert with_report["pdf_url"].startswith("http://testserver/")
    assert with_report["pdf_url"].endswith(f"pentest_scan_{scan.uuid}.pdf")


def test_the_scan_serializer_names_neither_the_recipient_nor_the_preflight_report():
    from pentest.serializers import PentestScanSerializer

    fields = set(PentestScanSerializer.Meta.fields)
    assert fields == SERVED | {"engine_response"}
    assert not fields & {"recipient_email", "assurance", "user", "id"}


# ===========================================================================
# 2. The list: each row the record, without the engine's answer
# ===========================================================================


def test_the_scan_list_serves_each_row_s_record_without_its_engine_response():
    analyst = _user()
    engagement = _engagement(analyst)
    password = uuid.uuid4().hex[:12]
    scan = _completed_scan(analyst, engagement, password)
    stranger = _user()
    _completed_scan(stranger, _engagement(stranger), uuid.uuid4().hex[:12], engine_run_id="run-other")

    response = _client(analyst).get("/api/pentest/scans/")

    assert response.status_code == 200, response.content
    page = response.json()
    assert page["count"] == 1, "another tenant's scan was listed"
    (row,) = page["results"]
    assert set(row) == SERVED
    assert row["uuid"] == str(scan.uuid)
    assert row["target_url"] == f"https://{WITHHELD_USERINFO}@app.client.example/login"
    assert (row["status"], row["verdict"], row["verdict_label"]) == (
        PentestScan.STATUS_COMPLETED, PentestScan.VERDICT_READY_RESTRICTED, "Ready with restrictions",
    )
    assert row["engagement"]["id"] == engagement.pk and row["engagement"]["client_name"] == "Client plc"
    assert row["engine_run_id"] == "run-record-1" and row["stop"]["state"] == "delivered"
    assert row["collected_at"] is not None
    _nothing_sensitive(response, password)

    admin = _client(_user(User.Roles.ADMIN))
    assert admin.get("/api/pentest/scans/").json()["count"] == 2


# ===========================================================================
# 3. A stopped scan reads as stopped: no verdict, no report
# ===========================================================================


def test_a_stopped_scan_is_served_as_stopped_with_no_verdict_and_no_report():
    analyst = _user()
    scan = PentestScan.objects.create(
        user=analyst, engagement=_engagement(analyst), target_url="https://app.client.example/login", consent=True,
        status=PentestScan.STATUS_PENDING, engine_response=PARTIAL, engine_run_id="run-stopped-1",
        collected_at=timezone.now(),
    )
    scan.mark_stopped("Stopped on the engine: stopped by an operator")
    client = _client(analyst)

    detail = client.get(f"/api/pentest/scans/{scan.uuid}/").json()
    (row,) = client.get("/api/pentest/scans/").json()["results"]

    for body in (detail, row):
        assert body["status"] == STOPPED
        assert body["verdict"] is None and body["verdict_label"] is None
        assert body["pdf_url"] is None
        assert body["error_message"] == "Stopped on the engine: stopped by an operator"
        assert body["engine_run_id"] == "run-stopped-1" and body["collected_at"] is not None
    assert detail["engine_response"] == PARTIAL, "what the run had when it stopped was not served"
    assert "engine_response" not in row


# ===========================================================================
# 4. A finding names its scan and run; a deployment its engagement
# ===========================================================================


def test_a_finding_names_the_scan_and_run_it_came_from_and_a_deployment_its_engagement(
        django_capture_on_commit_callbacks):
    analyst = _user()
    engagement = _engagement(analyst)
    scan = PentestScan.objects.create(
        user=analyst, engagement=engagement, target_url="https://app.client.example/login", consent=True,
        status=PentestScan.STATUS_PENDING, engine_response={"findings": FINDINGS}, engine_run_id="run-join-1",
    )
    with django_capture_on_commit_callbacks(execute=True):
        scan.mark_completed()
    deployment = Deployment.objects.get()
    finding = Finding.objects.get()
    client = _client(analyst)

    listed = client.get("/api/assurance/findings/")
    assert listed.status_code == 200, listed.content
    rows = listed.json()
    rows = rows["results"] if isinstance(rows, dict) else rows
    (row,) = [r for r in rows if r["uuid"] == str(finding.uuid)]
    assert row["scan_uuid"] == str(scan.uuid)
    assert row["engine_run_id"] == "run-join-1"
    assert row["deployment_uuid"] == str(deployment.uuid)

    served = client.get(f"/api/assurance/deployments/{deployment.uuid}/")
    assert served.status_code == 200, served.content
    assert served.json()["engagement_id"] == engagement.pk
    assert served.json()["uuid"] == str(deployment.uuid)

    # A finding whose scan was trimmed away names none, rather than failing to serve.
    Finding.objects.filter(pk=finding.pk).update(scan=None)
    alone = client.get(f"/api/assurance/findings/{finding.uuid}/")
    assert alone.status_code == 200, alone.content
    assert (alone.json()["scan_uuid"], alone.json()["engine_run_id"]) == (None, None)
