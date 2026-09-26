"""Every writer that is not an API route keeps the stored decision current too.

Every write route refreshes the stored decision in its own transaction
(tests/test_every_write_route_keeps_the_decision_current.py). Nothing made
anything else do so: the Django admin wrote findings, assets and a deployment's
own inputs and recomputed nothing, and a shell or a management command could do
the same. The admin now refreshes in its own transaction; everything else is
caught by the backstop in `assurance.signals`, which schedules one refresh per
deployment for when the writing transaction commits -- coalesced, so an ingest of
a thousand findings is one recompute and not a thousand.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django import forms
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.test import Client
from django.utils import timezone
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import signals
from assurance.decision import compute_decision, recompute_decision
from assurance.models import (
    ApprovedWorkflow,
    Asset,
    DeclaredComponent,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
)
from tests.decision_surfaces import one_decision
from tests.signed_chains import record_signed

pytestmark = pytest.mark.django_db

User = get_user_model()


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _client():
    client = APIClient()
    client.force_authenticate(user=_admin())
    return client


def _scanned(name="d"):
    dep = Deployment.objects.create(name=f"{name}{Deployment.objects.count()}", owner=_admin())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    recompute_decision(dep)
    return dep


def _finding(dep, severity="critical", status=Finding.Status.OPEN, n="1"):
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{severity}-{n}", finding_type="t", title="T",
        severity=severity, status=status,
    )


def _stored(dep):
    return Deployment.objects.get(pk=dep.pk).decision


def _refreshes(callbacks):
    """The deployments the backstop scheduled a refresh for, one entry per hook."""
    return sorted(c.deployment_id for c in callbacks if isinstance(c, signals._RefreshAfterCommit))


# ------------------------------------------------ the Django admin


def _admin_web():
    web = Client()
    name = f"su{User.objects.count()}"
    web.force_login(User.objects.create_superuser(username=name, password="pw", email=f"{name}@example.com"))
    return web


def _change_form(web, url, **changes):
    """The change form as the page rendered it, with ``changes`` applied: every
    field the form carries, in the shape its widget reads it back."""
    response = web.get(url)
    assert response.status_code == 200
    form = response.context["adminform"].form
    data = {}
    for bound in form:
        value = changes.get(bound.name, bound.value())
        widget = bound.field.widget
        if isinstance(widget, forms.MultiWidget):
            for i, part in enumerate(widget.decompress(value)):
                data[f"{bound.html_name}_{i}"] = "" if part is None else part
        elif isinstance(widget, forms.CheckboxInput):
            if value:
                data[bound.html_name] = "on"
        else:
            prepared = bound.field.prepare_value(value)
            data[bound.html_name] = "" if prepared is None else prepared
    for inline in response.context["inline_admin_formsets"]:
        formset = inline.formset
        for name in ("TOTAL_FORMS", "INITIAL_FORMS", "MIN_NUM_FORMS", "MAX_NUM_FORMS"):
            data[f"{formset.prefix}-{name}"] = formset.management_form[name].value()
    return data


def _saved(response):
    assert response.status_code == 302, (
        response.context["adminform"].form.errors if response.context else response.content[:500]
    )


def test_an_admin_edit_of_a_deployments_own_input_refreshes_its_decision():
    """`evidence_incomplete` is an input the deployment row carries. The admin wrote
    it and recomputed nothing: decision-support said NEEDS_MORE_EVIDENCE beside a
    stored READY. Run inside the test's transaction, so the after-commit backstop
    never fires -- what is tested is the admin's own refresh."""
    dep = _scanned()
    web = _admin_web()
    url = f"/admin/assurance/deployment/{dep.pk}/change/"
    _saved(web.post(url, _change_form(web, url, evidence_incomplete=True)))
    assert Deployment.objects.get(pk=dep.pk).evidence_incomplete is True
    assert one_decision(dep, _client()) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_an_admin_reopening_a_critical_finding_refreshes_the_decision():
    dep = _scanned()
    finding = _finding(dep, status=Finding.Status.CLOSED)
    recompute_decision(dep)
    web = _admin_web()
    url = f"/admin/assurance/finding/{finding.pk}/change/"
    _saved(web.post(url, _change_form(web, url, status=Finding.Status.OPEN)))
    assert one_decision(dep, _client()) == Deployment.Decision.NOT_RECOMMENDED


def test_an_admin_moving_a_finding_to_another_deployment_refreshes_both():
    here = _scanned("here")
    there = _scanned("there")
    finding = _finding(here)
    recompute_decision(here)
    web = _admin_web()
    url = f"/admin/assurance/finding/{finding.pk}/change/"
    _saved(web.post(url, _change_form(web, url, deployment=there.pk)))
    client = _client()
    assert one_decision(here, client) == Deployment.Decision.READY
    assert one_decision(there, client) == Deployment.Decision.NOT_RECOMMENDED


def test_an_admin_deleting_a_finding_refreshes_the_decision():
    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    web = _admin_web()
    _saved(web.post(f"/admin/assurance/finding/{finding.pk}/delete/", {"post": "yes"}))
    assert one_decision(dep, _client()) == Deployment.Decision.READY


def test_an_admin_bulk_delete_refreshes_the_decision_in_the_deletes_transaction(monkeypatch):
    """The changelist's bulk delete is not wrapped in a transaction by the admin, as
    the change form is. Refreshed after the delete had committed, a reader in
    between would see the finding gone and the decision it held still standing."""
    from assurance import admin as assurance_admin

    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    # The test runs inside pytest-django's transaction, so "in an atomic block" is
    # always true here and would assert nothing: the depth has to grow.
    outside = len(connection.atomic_blocks)
    depths = []
    real = assurance_admin.refresh_stored_decisions

    def recording(deployment_ids):
        depths.append(len(connection.atomic_blocks))
        return real(deployment_ids)

    monkeypatch.setattr(assurance_admin, "refresh_stored_decisions", recording)
    web = _admin_web()
    response = web.post(
        "/admin/assurance/finding/",
        {"action": "delete_selected", "_selected_action": [finding.pk], "post": "yes"},
    )
    assert response.status_code == 302
    assert not Finding.objects.filter(pk=finding.pk).exists()
    assert depths and all(depth > outside for depth in depths), (outside, depths)
    assert one_decision(dep, _client()) == Deployment.Decision.READY


def test_an_admin_edit_of_an_asset_refreshes_the_decision():
    """The declared component was observed and assessed, so the audit was complete.
    Renaming the asset leaves the declaration unobserved: AUDIT_INCOMPLETE."""
    dep = _scanned()
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt")
    asset = Asset.objects.create(
        deployment=dep, kind=Asset.Kind.MODEL, classification=Asset.Classification.KNOWN,
        name="gpt", identifier="gpt", assessed_at=timezone.now(),
    )
    recompute_decision(dep)
    assert one_decision(dep, _client()) == Deployment.Decision.READY
    web = _admin_web()
    url = f"/admin/assurance/asset/{asset.pk}/change/"
    _saved(web.post(url, _change_form(web, url, name="renamed", identifier="renamed")))
    assert one_decision(dep, _client()) == Deployment.Decision.AUDIT_INCOMPLETE


# ------------------------------------------------ the backstop: every other writer


@pytest.fixture
def commit(django_capture_on_commit_callbacks):
    """Run a block as though its transaction committed at the end of it: the hooks
    it registered run. The test's own transaction never commits, so without this a
    refresh scheduled while setting up would still be pending when the write under
    test is made -- and would, correctly, stand for that write's refresh too, which
    is not what the test is asking about."""
    return lambda: django_capture_on_commit_callbacks(execute=True)


def test_a_shell_write_refreshes_the_stored_decision_when_it_commits(commit):
    with commit():
        dep = _scanned()
        finding = _finding(dep, status=Finding.Status.CLOSED)
    assert _stored(dep) == Deployment.Decision.READY
    with commit() as callbacks:
        finding.status = Finding.Status.OPEN
        finding.save()
    assert _refreshes(callbacks) == [dep.pk]
    assert one_decision(dep, _client()) == Deployment.Decision.NOT_RECOMMENDED


def test_a_deployment_input_written_from_a_shell_refreshes_too(commit):
    with commit():
        dep = _scanned()
    with commit():
        dep.evidence_incomplete = True
        dep.save(update_fields=["evidence_incomplete", "updated_at"])
    assert one_decision(dep, _client()) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_many_writes_in_one_transaction_refresh_once_per_deployment(commit, django_capture_on_commit_callbacks):
    """An ingest writes a finding, its evidence and its assets per row. Scheduled
    per row it is O(rows) recomputes under the row lock; coalesced it is one."""
    with commit():
        one, other = _scanned("one"), _scanned("other")
    with django_capture_on_commit_callbacks() as callbacks:
        for n in range(25):
            finding = _finding(one, severity="low", n=str(n))
            Evidence.objects.create(finding=finding, classification=EvidenceClass.TECHNICALLY_VERIFIED)
            finding.status = Finding.Status.CLOSED
            finding.save()
        _finding(other, severity="low")
    assert _refreshes(callbacks) == sorted([one.pk, other.pk])


def test_an_evidence_row_saved_with_its_finding_at_hand_asks_nothing_more(
    commit, django_capture_on_commit_callbacks, django_assert_num_queries
):
    """An ingest writes an evidence row per finding, with the finding in hand. The
    backstop reads the deployment off it rather than asking the database: one
    INSERT, and nothing else, per row."""
    with commit():
        dep = _scanned()
        finding = _finding(dep, severity="low")
    with django_capture_on_commit_callbacks() as callbacks, django_assert_num_queries(1):
        Evidence.objects.create(finding=finding, classification=EvidenceClass.UNKNOWN)
    assert _refreshes(callbacks) == [dep.pk]


def test_the_refreshs_own_save_schedules_nothing(commit, django_capture_on_commit_callbacks):
    """The refresh writes the deployment row. Scheduling on that write would make
    every refresh schedule the next."""
    with commit():
        dep = _scanned()
        _finding(dep)
    with django_capture_on_commit_callbacks() as callbacks:
        assert recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True) == Deployment.Decision.PAUSED
        assert recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False) == Deployment.Decision.NOT_RECOMMENDED
    assert _refreshes(callbacks) == []


def test_a_fixture_load_schedules_nothing(commit, django_capture_on_commit_callbacks):
    """`loaddata` saves raw: rows restored as they were dumped, stored decision
    included, and not necessarily parents first."""
    with commit():
        dep = _scanned()
        finding = _finding(dep, status=Finding.Status.CLOSED)
    with django_capture_on_commit_callbacks() as callbacks:
        finding.status = Finding.Status.OPEN
        finding.save_base(raw=True)
        Deployment.objects.get(pk=dep.pk).save_base(raw=True)
    assert _refreshes(callbacks) == []


def test_a_remediation_move_schedules_nothing(commit, django_capture_on_commit_callbacks):
    """The remediation workflow saves the finding on a column the decision does not
    read."""
    from assurance.remediation import apply_transition

    with commit():
        dep = _scanned()
        finding = _finding(dep)
    with django_capture_on_commit_callbacks() as callbacks:
        apply_transition(finding, Finding.RemediationState.TRIAGED, actor=dep.owner)
    assert _refreshes(callbacks) == []


def test_a_refresh_dropped_with_a_rolled_back_savepoint_is_scheduled_again(commit, django_capture_on_commit_callbacks):
    """Django discards the hooks a rolled-back savepoint registered. A later write in
    the same transaction must not take the discarded one for pending, or its
    refresh is lost."""
    with commit():
        dep = _scanned()
        finding = _finding(dep, severity="low")
    with django_capture_on_commit_callbacks() as callbacks:
        try:
            with transaction.atomic():
                finding.status = Finding.Status.CLOSED
                finding.save()
                raise RuntimeError("rolled back")
        except RuntimeError:
            pass
        finding.refresh_from_db()
        finding.status = Finding.Status.CLOSED
        finding.save()
    assert _refreshes(callbacks) == [dep.pk]


def test_moving_a_row_to_another_deployment_refreshes_both(commit):
    with commit():
        here, there = _scanned("here"), _scanned("there")
        finding = _finding(here)
    with commit() as callbacks:
        finding.deployment = there
        finding.save()
    assert _refreshes(callbacks) == sorted([here.pk, there.pk])
    client = _client()
    assert one_decision(here, client) == Deployment.Decision.READY
    assert one_decision(there, client) == Deployment.Decision.NOT_RECOMMENDED


def test_deleting_an_input_refreshes_and_deleting_the_deployment_does_not(commit):
    with commit():
        dep = _scanned()
        finding = _finding(dep)
        Evidence.objects.create(finding=finding, classification=EvidenceClass.UNKNOWN)
    with commit() as callbacks:
        Finding.objects.filter(pk=finding.pk).delete()
    assert _refreshes(callbacks) == [dep.pk]
    assert one_decision(dep, _client()) == Deployment.Decision.READY

    with commit():
        gone = _scanned("gone")
        Evidence.objects.create(finding=_finding(gone), classification=EvidenceClass.UNKNOWN)
    with commit() as callbacks:
        Deployment.objects.filter(pk=gone.pk).delete()
    assert _refreshes(callbacks) == []


def test_a_refresh_for_a_deployment_deleted_before_commit_is_skipped(commit):
    with commit():
        dep = _scanned()
    with commit() as callbacks:
        _finding(dep)
        Deployment.objects.filter(pk=dep.pk).delete()
    assert _refreshes(callbacks) == [dep.pk]


def test_a_backstop_refresh_that_fails_is_logged_not_raised(commit, monkeypatch, caplog):
    """By commit time the write has committed. Raised, the failure would reach a
    caller whose write stands -- an API route that already refreshed in its own
    transaction would answer 500 and be retried -- and drop every hook after it."""
    from assurance import decision as decision_module

    with commit():
        dep = _scanned()

    def fails(deployment, **kwargs):
        raise RuntimeError("the refresh failed")

    monkeypatch.setattr(decision_module, "recompute_decision", fails)
    with commit():
        _finding(dep)
    assert "stored decision refresh failed after commit" in caplog.text


def test_a_provider_write_refreshes_every_deployment_serving_through_it(commit):
    """A provider's name and region are fields of the served route every chain
    outcome is compared with (P2.2), and a provider is shared: renaming it moves the
    route -- and the decision -- of each deployment with a component resolving to
    it, with no write to any of them. Deleting it moves them too."""
    from assurance.models import Provider

    with commit():
        serving, other, unrelated = _scanned("serving"), _scanned("other"), _scanned("unrelated")
        provider = Provider.objects.create(name="VendorX", kind=Provider.Kind.MODEL_PROVIDER)
        for dep in (serving, other):
            Asset.objects.create(
                deployment=dep, kind=Asset.Kind.MODEL, name="m", identifier="m", provider=provider,
                metadata={"model": "x"},
            )
    with commit() as callbacks:
        provider.name = "VendorY"
        provider.save()
    assert _refreshes(callbacks) == sorted([serving.pk, other.pk])
    assert unrelated.pk not in _refreshes(callbacks)

    with commit() as callbacks:
        provider.delete()
    assert _refreshes(callbacks) == sorted([serving.pk, other.pk])


def test_the_backstop_watches_every_table_the_decision_reads(engine_keyring):
    """The backstop is only as good as its list of inputs. Every table the decision
    rule queries must be the deployment's own or one the backstop watches, so an
    input added to the rule without being added to the backstop fails here."""
    import re

    from django.apps import apps
    from django.test.utils import CaptureQueriesContext

    from assurance.claims import derive_claims

    dep = _scanned()
    finding = _finding(dep, severity="low")
    Evidence.objects.create(finding=finding, classification=EvidenceClass.UNKNOWN)
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt")
    Asset.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt")
    ApprovedWorkflow.objects.create(deployment=dep, slug="refund-over-limit", name="refund")
    record_signed(dep, "refund-over-limit", oc.HELD, datetime.now(dt_timezone.utc) - timedelta(minutes=5))
    derive_claims(dep)
    with CaptureQueriesContext(connection) as queries:
        compute_decision(Deployment.objects.get(pk=dep.pk))
    by_table = {model._meta.db_table: model._meta.label for model in apps.get_models()}
    read = {
        by_table[table]
        for query in queries.captured_queries
        for table in re.findall(r'(?:FROM|JOIN)\s+"(\w+)"', query["sql"])
    }
    # A fan-out input -- a provider, which a deployment's served route names -- is
    # watched too: a write to it refreshes every deployment it reaches.
    inputs = set(signals.DECISION_INPUTS) | set(signals.DECISION_FANOUT_INPUTS)
    watched = inputs | {"assurance.Deployment"}
    assert read - watched == set(), f"the decision reads {sorted(read - watched)}, which nothing refreshes it on"
    # And the list names nothing the rule has stopped reading, which would only
    # cost refreshes. (The deployment's own row is read by the refresh under its
    # lock, not by the rule.)
    assert inputs - read == set(), sorted(inputs - read)


def test_the_decision_reads_no_finding_column_but_these():
    """A finding saved on a column outside `DECISION_COLUMNS` schedules no refresh,
    so no such column may move the decision. Each one is changed here, alone, on a
    finding that places the deployment, and the decision must not move."""
    from django.db import models as dj_models

    columns = signals.DECISION_COLUMNS["assurance.Finding"]
    dep = _scanned()
    other = _scanned("other")
    finding = _finding(dep, severity="high")
    asset = Asset.objects.create(deployment=dep, kind=Asset.Kind.MODEL, name="m", identifier="m")
    decided = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert decided == Deployment.Decision.NEEDS_REMEDIATION
    changed = []
    for field in Finding._meta.concrete_fields:
        if field.primary_key or field.name in columns or field.attname in columns:
            continue
        if field.choices:
            current = getattr(finding, field.attname)
            value = next(choice for choice, _ in field.choices if choice != current)
        elif isinstance(field, dj_models.ForeignKey):
            value = {"assurance.Asset": asset.pk, "assurance.Deployment": other.pk}.get(
                field.related_model._meta.label, None
            )
            if value is None and not field.null:
                continue
        elif isinstance(field, dj_models.BooleanField):
            value = not getattr(finding, field.attname)
        elif isinstance(field, (dj_models.DateTimeField, dj_models.DateField)):
            value = timezone.now() - timedelta(days=400)
        elif isinstance(field, dj_models.JSONField):
            value = {"changed": True}
        elif isinstance(field, (dj_models.FloatField, dj_models.IntegerField, dj_models.DecimalField)):
            value = 7
        elif isinstance(field, dj_models.UUIDField):
            import uuid

            value = uuid.uuid4()
        else:
            value = "changed"
        before = {f.attname: getattr(finding, f.attname) for f in Finding._meta.concrete_fields}
        Finding.objects.filter(pk=finding.pk).update(**{field.attname: value})
        assert compute_decision(Deployment.objects.get(pk=dep.pk)) == decided, field.name
        Finding.objects.filter(pk=finding.pk).update(**{field.attname: before[field.attname]})
        changed.append(field.name)
    assert "remediation_state" in changed and "assignee" in changed


# ------------------------------------------------ an ingest is one transaction


def _scan(owner, findings):
    from pentest.models import PentestScan

    return PentestScan.objects.create(
        user=owner,
        target_url="https://app.example/",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": findings},
    )


def test_an_ingest_that_fails_part_way_records_nothing(monkeypatch):
    """A reader mid-ingest saw the new findings beside the decision from before
    them, and an ingest that failed part way left them there for good."""
    from assurance import ingest, unknowns

    dep = _scanned()

    def fails(deployment):
        raise RuntimeError("the ingest failed part way")

    monkeypatch.setattr(unknowns, "derive_unknowns", fails)
    with pytest.raises(RuntimeError):
        ingest.ingest_scan(
            _scan(dep.owner, [{"type": "sqli", "severity": "critical", "title": "SQLi"}]), deployment=dep
        )
    assert not Finding.objects.filter(deployment=dep).exists()
    assert one_decision(dep, _client()) == Deployment.Decision.READY


@pytest.mark.django_db(transaction=True)
def test_an_ingest_outside_a_transaction_refreshes_a_fixed_number_of_times(monkeypatch):
    """Out of any transaction every write commits on its own, and the backstop runs
    at once. Before the ingest became one transaction, that was a recompute per
    finding and per evidence row."""
    from assurance import decision as decision_module
    from assurance import ingest

    real = decision_module.recompute_decision

    def count(n):
        dep = _scanned(f"n{n}")
        calls = []

        def counting(deployment, **kwargs):
            calls.append(deployment.pk)
            return real(deployment, **kwargs)

        monkeypatch.setattr(decision_module, "recompute_decision", counting)
        try:
            ingest.ingest_scan(
                _scan(dep.owner, [{"type": f"t{i}", "severity": "low", "title": f"T{i}"} for i in range(n)]),
                deployment=dep,
            )
        finally:
            monkeypatch.setattr(decision_module, "recompute_decision", real)
        assert _stored(dep) == compute_decision(Deployment.objects.get(pk=dep.pk))
        return len(calls)

    few, many = count(1), count(20)
    assert few == many, (few, many)
    assert many <= 2, many
