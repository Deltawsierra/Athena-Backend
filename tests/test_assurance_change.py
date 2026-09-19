"""Athena spine (EXPOSE) — Change Intelligence + evidence expiration.

Proves the change state of a finding is read honestly from the timestamps that
already exist: new the first time a scan reports it, recurring when a later scan
reports it again, and "no longer reported" (never "fixed") when the latest scan
drops it. Evidence expires: a finding not re-observed within the TTL is stale and
due a retest. Nothing new is detected — this only surfaces first_seen/last_seen.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import change
from assurance.models import Deployment, Finding
from assurance.views import FindingViewSet
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(dep, fp, first_seen, last_seen, **extra):
    return Finding.objects.create(
        deployment=dep, fingerprint=fp, finding_type="x", title=f"F {fp}",
        severity="high", first_seen=first_seen, last_seen=last_seen, **extra,
    )


def test_change_status_new_recurring_and_cleared():
    dep = Deployment.objects.create(name="d", owner=_user())
    now = timezone.now()
    t0, t2 = now - timedelta(days=7), now
    # Present in the latest scan for the first time.
    new = _finding(dep, "new", first_seen=t2, last_seen=t2)
    # Seen a week ago and again in the latest scan.
    recurring = _finding(dep, "rec", first_seen=t0, last_seen=t2)
    # Seen a week ago, absent from the latest scan.
    cleared = _finding(dep, "gone", first_seen=t0, last_seen=t0)

    latest = change.latest_seen_by_deployment(Finding.objects.all())
    boundary = latest[dep.pk]
    assert change.change_status(new, boundary) == "new"
    assert change.change_status(recurring, boundary) == "recurring"
    assert change.change_status(cleared, boundary) == "cleared"


def test_cleared_is_not_fixed_wording():
    # The label must never imply remediation — absence of a signal is not a fix.
    assert change.CHANGE_LABELS["cleared"] == "No longer reported"


def test_evidence_expiration_is_measured_from_last_seen():
    dep = Deployment.objects.create(name="d", owner=_user())
    now = timezone.now()
    fresh = _finding(dep, "fresh", first_seen=now, last_seen=now)
    stale = _finding(dep, "stale", first_seen=now - timedelta(days=200),
                     last_seen=now - timedelta(days=change.EVIDENCE_TTL_DAYS + 5))

    assert change.is_stale(fresh, now) is False
    assert change.is_stale(stale, now) is True
    assert change.age_days(stale, now) == change.EVIDENCE_TTL_DAYS + 5


def test_a_single_scan_makes_every_finding_new_not_cleared():
    """With only one scan on record, nothing is 'cleared' — there is no earlier
    scan for anything to have disappeared from."""
    dep = Deployment.objects.create(name="d", owner=_user())
    now = timezone.now()
    for i in range(3):
        _finding(dep, f"f{i}", first_seen=now, last_seen=now)
    boundary = change.latest_seen_by_deployment(Finding.objects.all())[dep.pk]
    statuses = {change.change_status(f, boundary) for f in dep.findings.all()}
    assert statuses == {"new"}


def test_finding_api_exposes_change_status_and_staleness():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    now = timezone.now()
    _finding(dep, "rec", first_seen=now - timedelta(days=120), last_seen=now)  # recurring, fresh
    _finding(dep, "gone", first_seen=now - timedelta(days=120),
             last_seen=now - timedelta(days=120))  # cleared, stale

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})
    request = factory.get("/api/assurance/findings/")
    force_authenticate(request, user=admin)
    resp = view(request)
    assert resp.status_code == 200
    rows = resp.data["results"] if isinstance(resp.data, dict) else resp.data
    by_fp = {r["title"]: r for r in rows}

    rec = by_fp["F rec"]
    assert rec["change_status"] == "recurring"
    assert rec["change_label"] == "Recurring"
    assert rec["stale"] is False

    gone = by_fp["F gone"]
    assert gone["change_status"] == "cleared"
    assert gone["change_label"] == "No longer reported"
    assert gone["stale"] is True
    assert gone["age_days"] >= change.EVIDENCE_TTL_DAYS


def test_change_boundary_ignores_the_status_filter():
    """The 'latest scan' boundary is a fact about the deployment: filtering the
    view to ?status=open must not redefine it and mislabel a cleared finding."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    now = timezone.now()
    # The only finding in the latest scan is closed (human-set); the open one is
    # from an earlier scan. If the boundary were computed from the ?status=open
    # subset, the open finding would look current instead of cleared.
    _finding(dep, "latest", first_seen=now, last_seen=now, status=Finding.Status.CLOSED)
    _finding(dep, "old", first_seen=now - timedelta(days=30),
             last_seen=now - timedelta(days=30), status=Finding.Status.OPEN)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})
    request = factory.get("/api/assurance/findings/?status=open")
    force_authenticate(request, user=admin)
    resp = view(request)
    rows = resp.data["results"] if isinstance(resp.data, dict) else resp.data
    assert len(rows) == 1
    assert rows[0]["title"] == "F old"
    assert rows[0]["change_status"] == "cleared"  # not "recurring"


def test_latest_scan_boundary_is_privilege_independent():
    """L2: for a non-privileged caller who can see only a subset of a deployment's
    findings, the latest-scan boundary is still the deployment's *true* latest — so
    a finding absent from the newest scan reads 'cleared', not mislabeled current.

    Before the fix the boundary was computed over the caller's visible subset, so
    the viewer below (who sees only their own older finding) would read it as
    'recurring'; computing the boundary over all findings makes it 'cleared'."""
    owner = _user("owner", role=User.Roles.ADMIN)
    viewer = _user("viewer", role=User.Roles.VIEWER)  # non-privileged: sees only their own
    dep = Deployment.objects.create(name="d", owner=owner)
    now = timezone.now()
    # The viewer's own older scan produced this finding (they can see it).
    mine_scan = PentestScan.objects.create(user=viewer, target_url="https://a/", consent=True)
    _finding(
        dep, "mine", first_seen=now - timedelta(days=10),
        last_seen=now - timedelta(days=10), scan=mine_scan,
    )
    # A newer scan by someone else on the same deployment — invisible to the viewer,
    # but it defines the deployment's true latest boundary.
    theirs_scan = PentestScan.objects.create(user=owner, target_url="https://a/", consent=True)
    _finding(dep, "theirs", first_seen=now, last_seen=now, scan=theirs_scan)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})
    request = factory.get("/api/assurance/findings/")
    force_authenticate(request, user=viewer)
    resp = view(request)
    assert resp.status_code == 200
    rows = resp.data["results"] if isinstance(resp.data, dict) else resp.data
    assert {r["title"] for r in rows} == {"F mine"}  # viewer sees only their own finding
    assert rows[0]["change_status"] == "cleared"  # judged against the true latest scan
