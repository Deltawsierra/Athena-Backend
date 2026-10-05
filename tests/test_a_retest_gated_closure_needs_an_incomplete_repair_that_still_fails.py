"""A retest-gated closure needs a planted incomplete repair that still fails.

FREEZE.md: "No closing remediation because a ticket status changed -- closure is
effect-backed only." A finding carrying ``retest_required`` could be marked CLOSED
(or its remediation RESOLVED) by a PATCH, the admin, or the remediation workflow
with nothing behind the click. Now every such move goes through
``assurance.retest_closure`` and stands only on a record showing the check failed
on the vulnerable fixture, passed on the repaired and benign ones, and still failed
on each of six planted incomplete repairs -- each of which, had it passed, would
have let a cosmetic fix close the finding.
"""

from __future__ import annotations

import copy
import inspect
import re
from datetime import timedelta
from pathlib import Path

import pytest
from django import forms
from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import ingest
from assurance.models import ClaimEvidence, Deployment, Finding, RetestClosureEvidence
from assurance.remediation import apply_transition
from assurance.retest_closure import (
    FIXTURE_CLASSES,
    INCOMPLETE_REPAIR,
    INCOMPLETE_REPAIR_PATTERNS,
    ClosureRefused,
    record_closure_evidence,
)
from assurance.views import FindingViewSet
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
State = Finding.RemediationState
REPO = Path(__file__).resolve().parent.parent

COMPLETE = {
    "vulnerable": {"ran": True, "outcome": "failed"},
    "repaired": {"ran": True, "outcome": "passed"},
    "benign": {"ran": True, "outcome": "passed"},
    INCOMPLETE_REPAIR: {p: {"ran": True, "outcome": "failed"} for p in INCOMPLETE_REPAIR_PATTERNS},
}


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _finding(retest_required=True, **kwargs):
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    defaults = dict(
        deployment=dep, fingerprint="fp", finding_type="sql_injection", title="SQLi",
        severity="critical", retest_required=retest_required,
    )
    defaults.update(kwargs)
    return Finding.objects.create(**defaults)


def _record(finding, fixtures=None, *, origin=ClaimEvidence.Origin.INDEPENDENT, digest="sha256:ab12", now=None):
    return record_closure_evidence(
        finding, fixtures=copy.deepcopy(COMPLETE if fixtures is None else fixtures),
        origin=origin, content_digest=digest, now=now,
    )


def _refused(finding, *names):
    finding_row = Finding.objects.get(pk=finding.pk)
    with pytest.raises(ClosureRefused) as caught:
        finding_row.status = Finding.Status.CLOSED
        finding_row.save()
    assert Finding.objects.get(pk=finding.pk).status != Finding.Status.CLOSED
    text = "; ".join(caught.value.reasons)
    for name in names:
        assert name in text, text
    return text


# ------------------------------------------------ the six planted incomplete repairs


@pytest.mark.parametrize("pattern", INCOMPLETE_REPAIR_PATTERNS)
def test_a_planted_incomplete_repair_that_passed_is_refused(pattern):
    """Each pattern is its own fixture: had the check passed on it, the record would
    otherwise have closed the finding. The reason names the pattern."""
    finding = _finding()
    fooled = copy.deepcopy(COMPLETE)
    fooled[INCOMPLETE_REPAIR][pattern] = {"ran": True, "outcome": "passed"}
    _record(finding, fooled)
    text = _refused(finding, f"{INCOMPLETE_REPAIR}/{pattern}: passed")
    for other in set(INCOMPLETE_REPAIR_PATTERNS) - {pattern}:
        assert other not in text


def test_a_complete_record_closes():
    finding = _finding()
    _refused(finding, "no closure evidence recorded")
    _record(finding)
    finding.status = Finding.Status.CLOSED
    finding.save()
    assert Finding.objects.get(pk=finding.pk).status == Finding.Status.CLOSED


def test_a_later_fooled_run_outranks_an_earlier_complete_one():
    finding = _finding()
    _record(finding)
    fooled = copy.deepcopy(COMPLETE)
    fooled[INCOMPLETE_REPAIR]["displaced_effects"]["outcome"] = "passed"
    _record(finding, fooled, now=timezone.now() + timedelta(seconds=1))
    _refused(finding, "displaced_effects")


# ------------------------------------------------ missing, not run, unreadable, wrong


@pytest.mark.parametrize("fixture_class", FIXTURE_CLASSES)
def test_each_missing_fixture_class_is_refused(fixture_class):
    finding = _finding()
    fixtures = copy.deepcopy(COMPLETE)
    del fixtures[fixture_class]
    _record(finding, fixtures)
    _refused(finding, f"{fixture_class}: not recorded")


@pytest.mark.parametrize("pattern", INCOMPLETE_REPAIR_PATTERNS)
def test_each_missing_or_unrun_pattern_is_refused(pattern):
    finding = _finding()
    fixtures = copy.deepcopy(COMPLETE)
    del fixtures[INCOMPLETE_REPAIR][pattern]
    _record(finding, fixtures)
    _refused(finding, f"{INCOMPLETE_REPAIR}/{pattern}: not recorded")

    fixtures = copy.deepcopy(COMPLETE)
    fixtures[INCOMPLETE_REPAIR][pattern] = {"ran": False, "outcome": "failed"}
    _record(finding, fixtures, now=timezone.now() + timedelta(seconds=1))
    _refused(finding, f"{INCOMPLETE_REPAIR}/{pattern}: not run")


@pytest.mark.parametrize(
    "fixture_class, entry, expected",
    [
        ("vulnerable", {"ran": True, "outcome": "passed"}, "vulnerable: passed, a closure needs it failed"),
        ("repaired", {"ran": True, "outcome": "failed"}, "repaired: failed, a closure needs it passed"),
        ("benign", {"ran": True, "outcome": "failed"}, "benign: failed, a closure needs it passed"),
        ("repaired", {"ran": True, "outcome": "errored"}, "repaired: errored"),
        ("benign", {"ran": False}, "benign: not run"),
        ("vulnerable", "failed", "vulnerable: unreadable"),
        ("repaired", {"ran": True, "outcome": "fixed"}, "repaired: unreadable outcome"),
        (INCOMPLETE_REPAIR, ["restored_reachability"], f"{INCOMPLETE_REPAIR}: unreadable"),
    ],
)
def test_a_wrong_unrun_or_unreadable_class_is_refused(fixture_class, entry, expected):
    finding = _finding()
    fixtures = copy.deepcopy(COMPLETE)
    fixtures[fixture_class] = entry
    _record(finding, fixtures)
    _refused(finding, expected)


def test_no_record_an_unweighted_origin_a_blank_digest_or_a_stale_run_is_refused():
    finding = _finding()
    _refused(finding, "no closure evidence recorded")

    for origin in (ClaimEvidence.Origin.TARGET, ClaimEvidence.Origin.OPERATOR, ClaimEvidence.Origin.VENDOR):
        _record(finding, origin=origin)
        _refused(finding, f"origin: {origin}")

    _record(finding, digest="")
    _refused(finding, "content_digest: blank")

    # Recorded, then the scan saw the defect again: the path reopened after the retest.
    _record(finding)
    Finding.objects.filter(pk=finding.pk).update(last_seen=timezone.now() + timedelta(minutes=5))
    _refused(finding, "recorded before the finding was last observed")


def test_fixtures_that_are_not_a_mapping_are_unreadable_even_written_past_the_recorder():
    finding = _finding()
    RetestClosureEvidence.objects.create(
        finding=finding, fixtures=["vulnerable", "repaired"], origin="independent", content_digest="x"
    )
    _refused(finding, "fixtures: unreadable")


# ------------------------------------------------ every closing path goes through the gate


def _admin_web():
    web = Client()
    name = f"su{User.objects.count()}"
    web.force_login(User.objects.create_superuser(username=name, password="pw", email=f"{name}@example.com"))
    return web


def _admin_post(finding, **changes):
    web = _admin_web()
    url = f"/admin/assurance/finding/{finding.pk}/change/"
    response = web.get(url)
    assert response.status_code == 200
    form = response.context["adminform"].form
    assert "retest_required" not in form.fields  # the engine's flag; not unticked here
    data = {}
    for bound in form:
        changed = bound.name in changes
        value = changes[bound.name] if changed else bound.value()
        widget = bound.field.widget
        if isinstance(widget, forms.MultiWidget):
            for i, part in enumerate(widget.decompress(value)):
                data[f"{bound.html_name}_{i}"] = "" if part is None else part
        elif isinstance(widget, forms.CheckboxInput):
            if value:
                data[bound.html_name] = "on"
        else:
            prepared = bound.field.prepare_value(value) if changed else value
            data[bound.html_name] = "" if prepared is None else prepared
    for inline in response.context["inline_admin_formsets"]:
        formset = inline.formset
        for name in ("TOTAL_FORMS", "INITIAL_FORMS", "MIN_NUM_FORMS", "MAX_NUM_FORMS"):
            data[f"{formset.prefix}-{name}"] = formset.management_form[name].value()
    response = web.post(url, data)
    return response.status_code == 302


def _api_patch(finding):
    request = APIRequestFactory().patch(
        f"/api/assurance/findings/{finding.uuid}/", {"status": "closed"}, format="json"
    )
    force_authenticate(request, user=_admin())
    response = FindingViewSet.as_view({"patch": "partial_update"})(request, uuid=str(finding.uuid))
    return response.status_code == 200


def _to_review(finding):
    if finding.remediation_state == State.IN_REVIEW:
        return
    for state in (State.TRIAGED, State.IN_PROGRESS, State.IN_REVIEW):
        apply_transition(finding, state, actor=None)


def _api_transition(finding):
    _to_review(finding)
    request = APIRequestFactory().post(
        f"/api/assurance/findings/{finding.uuid}/remediation/transition/", {"to_state": "resolved"}, format="json"
    )
    force_authenticate(request, user=_admin())
    response = FindingViewSet.as_view({"post": "remediation_transition"})(request, uuid=str(finding.uuid))
    return response.status_code == 200


def _apply_transition(finding):
    _to_review(finding)
    try:
        apply_transition(finding, State.RESOLVED, actor=None)
    except ClosureRefused:
        assert finding.remediation_state == State.IN_REVIEW  # the caller's copy too
        return False
    return True


def _orm(field, value):
    def write(finding):
        setattr(finding, field, value)
        try:
            finding.save(update_fields=[field, "updated_at"])
        except ClosureRefused:
            return False
        return True

    return write


# The closing paths of step 0: every writer that can move a Finding to
# status=closed or remediation_state=resolved.
CLOSING_PATHS = {
    "api PATCH status=closed": (_api_patch, "status"),
    "admin change form status=closed": (lambda f: _admin_post(f, status="closed"), "status"),
    "admin change form remediation_state=resolved": (
        lambda f: _admin_post(f, remediation_state="resolved"), "remediation_state"),
    "api remediation/transition to resolved": (_api_transition, "remediation_state"),
    "remediation.apply_transition to resolved": (_apply_transition, "remediation_state"),
    "ORM save status=closed": (_orm("status", Finding.Status.CLOSED), "status"),
    "ORM save remediation_state=resolved": (_orm("remediation_state", State.RESOLVED), "remediation_state"),
}
_CLOSED = {"status": Finding.Status.CLOSED, "remediation_state": State.RESOLVED}


@pytest.mark.parametrize("path", sorted(CLOSING_PATHS))
def test_every_closing_path_is_refused_without_closure_evidence(path):
    write, field = CLOSING_PATHS[path]
    finding = _finding()
    assert write(finding) is False
    assert getattr(Finding.objects.get(pk=finding.pk), field) != _CLOSED[field]


@pytest.mark.parametrize("path", sorted(CLOSING_PATHS))
def test_every_closing_path_closes_on_a_complete_record(path):
    write, field = CLOSING_PATHS[path]
    finding = _finding()
    assert write(finding) is False  # the same write, before the record exists
    _record(finding)
    assert write(Finding.objects.get(pk=finding.pk)) is True
    assert getattr(Finding.objects.get(pk=finding.pk), field) == _CLOSED[field]


@pytest.mark.parametrize("path", sorted(CLOSING_PATHS))
def test_every_closing_path_is_refused_on_a_fooled_record(path):
    write, field = CLOSING_PATHS[path]
    finding = _finding()
    fooled = copy.deepcopy(COMPLETE)
    fooled[INCOMPLETE_REPAIR]["restored_persistence"]["outcome"] = "passed"
    _record(finding, fooled)
    assert write(finding) is False
    assert getattr(Finding.objects.get(pk=finding.pk), field) != _CLOSED[field]


def test_a_finding_born_closed_with_a_retest_owed_is_refused():
    dep = Deployment.objects.create(name="born", owner=_admin())
    with pytest.raises(ClosureRefused):
        Finding.objects.create(
            deployment=dep, fingerprint="b", finding_type="t", title="T", severity="high",
            retest_required=True, status=Finding.Status.CLOSED,
        )
    assert not Finding.objects.filter(deployment=dep).exists()


def test_an_ingested_finding_owes_the_retest_and_its_patch_close_is_refused():
    """The real path: ingest marks a medium-or-worse finding retest_required, and a
    PATCH to closed on it is refused until the four classes stand behind it."""
    admin = _admin()
    scan = PentestScan.objects.create(
        user=admin, target_url="https://app.client.example/login", consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": [{"type": "sql_injection", "signature_id": "SQLI-001",
                                       "report_severity": "critical"}]},
    )
    ingest.ingest_scan(scan)
    finding = Finding.objects.get(finding_type="sql_injection")
    assert finding.retest_required is True
    assert _api_patch(finding) is False
    _record(finding)
    assert _api_patch(finding) is True


def test_no_code_path_writes_a_findings_disposition_past_save():
    """A queryset ``update``/``bulk_update`` skips :meth:`Finding.save` and so the
    gate. None writes ``status`` or ``remediation_state`` on findings; the one
    literal CLOSED write is bom_drift's machine close of its own drift findings,
    which never carry ``retest_required`` (only ingest writes that flag). And the
    save itself is the gate."""
    assert "enforce(" in inspect.getsource(Finding.save)
    assert "enforce(" in inspect.getsource(Finding.clean)
    sources = {
        p: p.read_text()
        for p in (REPO / "assurance").rglob("*.py")
        if "migrations" not in p.parts
    }
    bypass = re.compile(r"(\.update|bulk_update)\((?:[^()]|\([^()]*\))*\b(status|remediation_state)\b", re.S)
    for path, text in sources.items():
        for match in bypass.finditer(text):
            assert "Finding" not in match.group(0) and "findings" not in text[max(0, match.start() - 200):match.start()], (
                path, match.group(0)[:120])
    closers = sorted(p.name for p, t in sources.items() if re.search(r"(?<![=!<>])=\s*Finding\.Status\.CLOSED\b", t))
    assert closers == ["bom_drift.py"]
    flaggers = sorted(p.name for p, t in sources.items() if re.search(r"[\"']retest_required[\"']\s*:|\.retest_required\s*=", t))
    assert flaggers == ["ingest.py"]


# ------------------------------------------------ what is not a closure is untouched


@pytest.mark.parametrize(
    "status, extra",
    [
        (Finding.Status.ACCEPTED, {"risk_accepted_until": (timezone.now() + timedelta(days=30)).isoformat()}),
        (Finding.Status.FALSE_POSITIVE, {}),
        (Finding.Status.INVALIDATED, {}),
    ],
)
def test_accepted_false_positive_and_invalidated_are_not_closures(status, extra):
    finding = _finding()
    request = APIRequestFactory().patch(
        f"/api/assurance/findings/{finding.uuid}/", {"status": status, **extra}, format="json"
    )
    force_authenticate(request, user=_admin())
    response = FindingViewSet.as_view({"patch": "partial_update"})(request, uuid=str(finding.uuid))
    assert response.status_code == 200, response.data
    assert Finding.objects.get(pk=finding.pk).status == status
    # ...while the same finding, with the same (absent) evidence, is not closed.
    assert _api_patch(Finding.objects.get(pk=finding.pk)) is False


def test_a_finding_that_owes_no_retest_and_a_save_that_is_not_the_move_pass():
    plain = _finding(retest_required=False)
    assert _api_patch(plain) is True

    owed = _finding(fingerprint="fp2")
    _refused(owed, "no closure evidence recorded")
    _record(owed)
    owed.status = Finding.Status.CLOSED
    owed.save()
    # Already closed: a later save (an owner edit) is not a closure, and is not judged.
    RetestClosureEvidence.objects.filter(finding=owed).delete()
    owed.business_impact = "ledger"
    owed.save()
    assert Finding.objects.get(pk=owed.pk).business_impact == "ledger"
