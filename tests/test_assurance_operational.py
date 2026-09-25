"""Athena — Operational / continuous-assurance roll-up.

Proves the operational roll-up is an honest, REUSE-ONLY tie-together of the
existing continuous-assurance signals: evidence freshness/staleness (read from the
evidence-expiration signal in ``assurance.change``), the change/drift backlog
needing reassessment (read from the change-intelligence signal), remediation
velocity (reused from ``assurance.roi``), and the standing six-state decision.

Above all it proves the honesty invariants: stale evidence lowers freshness and is
surfaced, not hidden; a changed/drifted finding shows in the change backlog as
needing reassessment; open remediation is counted; the readiness band never reads
"steady"/healthy for a stale or empty deployment; there is no dollar figure
anywhere; ratios are None (not a fake 0%) with no basis; the output is
deterministic; the empty graph reads honestly; and the API read is open to any
operator.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.change import EVIDENCE_TTL_DAYS
from assurance.models import Deployment, Evidence, EvidenceClass, Finding, RemediationEvent
from assurance.operational import (
    READINESS_ATTENTION,
    READINESS_STALE,
    READINESS_STEADY,
    assess_operational,
)
from assurance.views import DeploymentViewSet
from assurance.revision import accept_transition

pytestmark = pytest.mark.django_db

User = get_user_model()

# A fixed clock for deterministic staleness across a test.
NOW = timezone.now()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(
    dep,
    finding_type="t",
    severity="high",
    *,
    status=Finding.Status.OPEN,
    remediation_state=Finding.RemediationState.NEW,
    evidence_class=None,
    first_seen=None,
    last_seen=None,
    n="1",
):
    f = Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{finding_type}-{n}",
        finding_type=finding_type,
        title=finding_type,
        severity=severity,
        status=status,
        remediation_state=remediation_state,
    )
    # first_seen/last_seen default to now(); override to control change/staleness.
    updates = []
    if first_seen is not None:
        f.first_seen = first_seen
        updates.append("first_seen")
    if last_seen is not None:
        f.last_seen = last_seen
        updates.append("last_seen")
    if updates:
        f.save(update_fields=updates)
    if evidence_class is not None:
        Evidence.objects.create(finding=f, classification=evidence_class, source="test")
    return f


def _walk_strings_and_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield ("key", k)
            yield from _walk_strings_and_keys(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _walk_strings_and_keys(item)
    elif isinstance(obj, str):
        yield ("value", obj)


def test_stale_evidence_lowers_freshness_and_is_surfaced_not_hidden():
    dep = Deployment.objects.create(name="d", owner=_user())
    # One finding observed recently (current), two observed long past the TTL (stale).
    _finding(dep, last_seen=NOW - timedelta(days=1), n="fresh")
    _finding(dep, last_seen=NOW - timedelta(days=EVIDENCE_TTL_DAYS + 5), n="stale1")
    _finding(dep, last_seen=NOW - timedelta(days=EVIDENCE_TTL_DAYS + 40), n="stale2")

    fresh = assess_operational(dep, now=NOW)["evidence_freshness"]
    assert fresh["total"] == 3
    assert fresh["current"] == 1
    # The stale count is surfaced, not hidden.
    assert fresh["stale"] == 2
    assert fresh["ttl_days"] == EVIDENCE_TTL_DAYS
    # A true ratio of real counts: 1 current of 3.
    assert fresh["freshness_ratio"] == round(1 / 3, 4)


def test_changed_finding_shows_in_change_backlog_as_needing_reassessment():
    dep = Deployment.objects.create(name="d", owner=_user())
    # latest scan boundary is NOW. A finding first==last at the boundary is NEW; a
    # finding whose last_seen is behind the boundary is CLEARED (no longer reported);
    # a finding seen before and again at the boundary is RECURRING (steady state).
    _finding(dep, first_seen=NOW, last_seen=NOW, n="new")
    _finding(dep, first_seen=NOW - timedelta(days=30), last_seen=NOW - timedelta(days=10), n="cleared")
    _finding(dep, first_seen=NOW - timedelta(days=30), last_seen=NOW, n="recurring")

    backlog = assess_operational(dep, now=NOW)["change_backlog"]
    assert backlog["total"] == 3
    assert backlog["new"] == 1
    assert backlog["cleared"] == 1
    assert backlog["recurring"] == 1
    # new + cleared changed and need a fresh look; recurring does not.
    assert backlog["needs_reassessment"] == 2
    assert backlog["needs_reassessment_ratio"] == round(2 / 3, 4)


def test_open_remediation_is_counted():
    dep = Deployment.objects.create(name="d", owner=_user())
    f1 = _finding(dep, remediation_state=Finding.RemediationState.IN_PROGRESS, n="a")
    _finding(dep, remediation_state=Finding.RemediationState.RESOLVED, n="b")
    _finding(dep, remediation_state=Finding.RemediationState.WONT_FIX, n="c")
    RemediationEvent.objects.create(finding=f1, from_state="triaged", to_state="in_progress")

    rem = assess_operational(dep, now=NOW)["remediation"]
    assert rem["open"] == 1  # only the in_progress one is open work
    assert rem["resolved"] == 1
    assert rem["wont_fix"] == 1
    assert rem["event_count"] == 1
    # Resolution is labelled a process claim (resolution_ratio), not security closure.
    assert rem["resolution_ratio"] == round(1 / 3, 4)


def test_readiness_never_reads_steady_for_a_stale_deployment():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Every finding's evidence is expired — nothing is current.
    _finding(dep, last_seen=NOW - timedelta(days=EVIDENCE_TTL_DAYS + 10), n="a")
    _finding(dep, last_seen=NOW - timedelta(days=EVIDENCE_TTL_DAYS + 20), n="b")

    result = assess_operational(dep, now=NOW)
    assert result["evidence_freshness"]["freshness_ratio"] == 0.0
    # A stale deployment is never green-by-default.
    assert result["readiness"] != READINESS_STEADY
    assert result["readiness"] == READINESS_STALE


def test_readiness_never_reads_steady_for_an_empty_deployment():
    dep = Deployment.objects.create(name="empty", owner=_user("empty-owner"))
    result = assess_operational(dep, now=NOW)
    # Nothing assessed — honest weakest band, not a clean pass.
    assert result["readiness"] == READINESS_STALE
    assert result["readiness"] != READINESS_STEADY


def test_a_current_low_backlog_deployment_can_earn_steady():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Current evidence, recurring (unchanged) findings, remediation resolved: every
    # signal is strong, so the band may legitimately read steady — earned, not default.
    for i in range(3):
        _finding(
            dep,
            first_seen=NOW - timedelta(days=30),
            last_seen=NOW,
            remediation_state=Finding.RemediationState.RESOLVED,
            n=f"r{i}",
        )
    result = assess_operational(dep, now=NOW)
    assert result["evidence_freshness"]["freshness_ratio"] == 1.0
    assert result["change_backlog"]["needs_reassessment"] == 0
    assert result["readiness"] == READINESS_STEADY


def test_open_remediation_lowers_readiness_off_steady():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Evidence current and unchanged, but all remediation is open work.
    for i in range(3):
        _finding(
            dep,
            first_seen=NOW - timedelta(days=30),
            last_seen=NOW,
            remediation_state=Finding.RemediationState.NEW,
            n=f"o{i}",
        )
    result = assess_operational(dep, now=NOW)
    # Fresh and unchanged, but open remediation is the weakest signal and sets the floor.
    assert result["evidence_freshness"]["freshness_ratio"] == 1.0
    assert result["summary"]["open_remediation"] == 3
    assert result["readiness"] != READINESS_STEADY


def test_no_dollar_figure_anywhere_in_the_output():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="critical", evidence_class=EvidenceClass.VENDOR_ASSERTED)

    result = assess_operational(dep, now=NOW)
    forbidden_keys = {
        "dollar", "dollars", "usd", "currency", "amount", "roi", "revenue",
        "loss", "losses", "arr", "acv", "cost", "savings", "price", "money",
    }
    for kind, text in _walk_strings_and_keys(result):
        low = text.lower()
        if kind == "key":
            assert low not in forbidden_keys, f"forbidden money key: {text!r}"
        assert "$" not in text and "€" not in text and "£" not in text


def test_ratios_are_none_not_a_fake_zero_with_no_basis():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = assess_operational(dep, now=NOW)
    fresh = result["evidence_freshness"]
    backlog = result["change_backlog"]
    # No findings → no basis to compute a ratio. None, never a fabricated 0%.
    assert fresh["total"] == 0
    assert fresh["freshness_ratio"] is None
    assert backlog["needs_reassessment_ratio"] is None
    assert result["remediation"]["resolution_ratio"] is None


def test_decision_is_reported_none_safe():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = assess_operational(dep, now=NOW)
    # No decision computed yet — never silently read as ready.
    assert result["decision"]["decision"] is None
    assert result["decision"]["decision_label"] is None

    # Through the boundary: `Deployment.save` refuses the decision columns.
    accept_transition(dep, to_decision=Deployment.Decision.NEEDS_REMEDIATION)
    result = assess_operational(dep, now=NOW)
    assert result["decision"]["decision"] == Deployment.Decision.NEEDS_REMEDIATION
    assert result["decision"]["decision_label"] == "Requires remediation"


def test_output_is_deterministic():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high", first_seen=NOW, last_seen=NOW, n="a")
    _finding(
        dep,
        "prompt_injection",
        "medium",
        last_seen=NOW - timedelta(days=EVIDENCE_TTL_DAYS + 1),
        remediation_state=Finding.RemediationState.IN_PROGRESS,
        n="b",
    )
    assert assess_operational(dep, now=NOW) == assess_operational(dep, now=NOW)


def test_empty_graph_reads_honestly_not_steady():
    dep = Deployment.objects.create(name="empty", owner=_user("e2"))
    result = assess_operational(dep, now=NOW)
    assert result["summary"]["total_findings"] == 0
    assert result["evidence_freshness"]["stale"] == 0
    assert result["evidence_freshness"]["current"] == 0
    assert result["readiness"] == READINESS_STALE
    # An honest empty read is not a green-by-default clean pass.
    assert result["readiness"] in {READINESS_STALE, READINESS_ATTENTION}
    assert result["readiness"] != READINESS_STEADY


def test_operational_assurance_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _finding(dep, severity="high", last_seen=NOW - timedelta(days=1))

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "operational_assurance"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/operational-assurance/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    # Shape: the documented return keys are present.
    assert set(resp.data) >= {
        "system", "decision", "evidence_freshness", "change_backlog",
        "remediation", "readiness", "summary",
    }
    assert resp.data["evidence_freshness"]["total"] == 1
