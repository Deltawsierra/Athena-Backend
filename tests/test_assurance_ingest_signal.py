"""Athena Phase 0.1b — ingestion is wired to scan completion.

Proves the post_save signal ingests a completed scan into the assurance system of
record, that it fires only on the completion transition, and that it never breaks
scan completion. The on-commit callback is forced with pytest-django's
``django_capture_on_commit_callbacks`` (in the ordinary rolled-back test
transaction it would not run — which is exactly why it cannot disturb the
existing pentest tests).
"""

from __future__ import annotations

from unittest import mock

import pytest
from django.contrib.auth import get_user_model

from assurance.models import Deployment, Finding
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()

FINDINGS = [
    {"type": "sql_injection", "report_severity": "critical", "confidence": 0.9,
     "tier": "confirmed", "exploit_like": True, "evidence": {"endpoint": "/search"}},
]


def _user():
    return User.objects.create_user(username="analyst", password="x", role=User.Roles.ANALYST)


def _pending_scan(user):
    return PentestScan.objects.create(
        user=user,
        target_url="https://app.client.example/login",
        consent=True,
        status=PentestScan.STATUS_PENDING,
        engine_response={"findings": FINDINGS},
    )


def test_completing_a_scan_ingests_its_findings(django_capture_on_commit_callbacks):
    user = _user()
    scan = _pending_scan(user)

    with django_capture_on_commit_callbacks(execute=True):
        scan.mark_completed()

    # The completion transition populated the system of record.
    assert Deployment.objects.count() == 1
    finding = Finding.objects.get()
    assert finding.finding_type == "sql_injection"
    assert finding.severity == "critical"
    assert finding.scan_id == scan.pk


def test_no_ingestion_on_a_non_completion_save(django_capture_on_commit_callbacks):
    user = _user()
    scan = _pending_scan(user)

    with django_capture_on_commit_callbacks(execute=True):
        # A save that does not set status to completed.
        scan.recipient_email = "ops@client.example"
        scan.save(update_fields=["recipient_email"])

    assert Finding.objects.count() == 0


def test_disable_flag_skips_ingestion(settings, django_capture_on_commit_callbacks):
    settings.ASSURANCE_INGEST_ON_COMPLETE = False
    user = _user()
    scan = _pending_scan(user)

    with django_capture_on_commit_callbacks(execute=True):
        scan.mark_completed()

    assert Finding.objects.count() == 0


def test_ingestion_failure_never_breaks_completion(django_capture_on_commit_callbacks):
    user = _user()
    scan = _pending_scan(user)

    with mock.patch("assurance.ingest.ingest_scan", side_effect=RuntimeError("boom")):
        with django_capture_on_commit_callbacks(execute=True):
            scan.mark_completed()  # must not raise

    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_COMPLETED  # completion still recorded
    assert Finding.objects.count() == 0  # ingestion swallowed the error
