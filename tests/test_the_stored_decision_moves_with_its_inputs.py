"""The stored decision moves with its inputs, in the same transaction as they do.

The receipt, the bundle, the deployment detail and the dispatch fence publish the
STORED decision; decision-support computes it live. Round seven found write routes
that never refreshed the stored decision and write routes that refreshed it in a
second transaction after the write had committed. Every route is held to both by
tests/test_every_write_route_keeps_the_decision_current.py; this file holds the
consequences one at a time -- the dispatch fence, a signed outcome's retry, a
reader in between -- and the pause decision-support publishes beside its revision.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.utils import timezone
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance.decision import compute_decision, decision_support, recompute_decision
from assurance.models import (
    ApprovedWorkflow,
    AssuranceClaim,
    Deployment,
    Finding,
    WorkflowChainOutcome,
)
from tests.decision_surfaces import one_decision
from tests.signed_chains import ENGINE_KEYS, record_signed

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


def _base(dep):
    return f"/api/assurance/deployments/{dep.uuid}/"


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


# ------------------------------------------------ the routes, one consequence at a time


def test_closing_the_last_critical_finding_reaches_every_surface():
    """The PATCH wrote the status and left the stored decision alone, in both
    directions: re-opening a critical left the receipt READY (the meta-test holds
    that one), and closing it left a NOT_RECOMMENDED nothing supported."""
    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    client = _client()
    assert one_decision(dep, client) == Deployment.Decision.NOT_RECOMMENDED
    response = client.patch(f"/api/assurance/findings/{finding.uuid}/", {"status": "closed"}, format="json")
    assert response.status_code == 200, response.content
    assert one_decision(dep, client) == Deployment.Decision.READY


def test_a_dispatch_retry_is_fenced_once_a_declaration_moves_the_decision(settings):
    """The push was authorized under a READY_RESTRICTED decision and lost. The
    declared architecture then held the deployment at AUDIT_INCOMPLETE -- live. The
    stored decision, and so the retry's fence, still said READY_RESTRICTED, and the
    retry pushed under an authority decision-support had already withdrawn."""
    import requests.exceptions as rex
    from cryptography.fernet import Fernet

    from assurance.dispatch import dispatch_finding, reconcile_attempt
    from assurance.models import ConnectorBinding, DispatchAttempt

    settings.ASSURANCE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    pushes = []

    class _Timeout:
        def post(self, url, *, headers, json):
            raise rex.ReadTimeout("the answer never came back")

    class _Accepting:
        def post(self, url, *, headers, json):
            pushes.append(url)

            class _Response:
                status_code = 201
                text = '{"key": "SEC-1"}'

                @staticmethod
                def json():
                    return {"key": "SEC-1", "id": "1"}

                @staticmethod
                def raise_for_status():
                    return None

            return _Response()

    dep = _scanned()
    finding = _finding(dep, severity="low")
    recompute_decision(dep)
    binding = ConnectorBinding(
        deployment=dep, connector="jira", enabled=True,
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    binding.set_secret("jira-tok")
    binding.save()
    first = dispatch_finding(finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Timeout)[0]
    assert first.policy_epoch == Deployment.Decision.READY_RESTRICTED
    reconcile_attempt(first, readback=lambda _op: False)

    client = _client()
    response = client.put(
        _base(dep) + "declared-architecture/", {"components": [{"kind": "model", "name": "never-observed"}]},
        format="json",
    )
    assert response.status_code == 200
    assert one_decision(dep, client) == Deployment.Decision.AUDIT_INCOMPLETE

    retry = dispatch_finding(
        Finding.objects.select_related("deployment").get(pk=finding.pk),
        trigger=DispatchAttempt.Trigger.SEVERITY,
        transport_factory=_Accepting,
    )[0]
    assert pushes == [], "a push went out under an authority decision-support had withdrawn"
    assert retry.outcome == DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED


def _signed_violation(dep):
    outcome = oc.build_outcome(
        deployment=str(dep.uuid), workflow="refund-over-limit", status=oc.VIOLATED, engine="achilles",
        engine_version="1.0.0", run_id="run-retry", evidence_digest="sha256:" + "ab" * 32,
        observed_at=datetime.now(dt_timezone.utc) - timedelta(minutes=1),
        reason="the gate refused the dispatch",
    )
    return oc.sign_outcome(outcome, ENGINE_KEYS["achilles"])


def test_a_signed_outcome_whose_refresh_failed_can_be_posted_again(engine_keyring, monkeypatch):
    """`ingest` committed the rows and the refresh ran after. A refresh that failed
    there (a lock timeout) left the violation recorded under a stored READY, and the
    engine's retry of the same envelope was refused as a replay -- so nothing could
    ever bring the two together. The rows now go with the refresh that failed, and
    the retry is simply the first successful post."""
    from django.db import OperationalError

    from assurance import views

    dep = Deployment.objects.create(name="obs", owner=_admin())
    ApprovedWorkflow.objects.create(deployment=dep, slug="refund-over-limit", name="refund")
    record_signed(dep, "refund-over-limit", oc.HELD, datetime.now(dt_timezone.utc) - timedelta(minutes=10))
    recompute_decision(dep)
    client = _client()
    assert one_decision(dep, client) == Deployment.Decision.READY

    real = views.recompute_decision
    failures = [OperationalError("database is locked")]

    def fails_once(deployment, **kwargs):
        if failures:
            raise failures.pop()
        return real(deployment, **kwargs)

    monkeypatch.setattr(views, "recompute_decision", fails_once)
    client.raise_request_exception = False
    url = _base(dep) + "chain-outcomes/observed/"
    violated = _signed_violation(dep)
    assert client.post(url, violated, format="json").status_code == 500
    assert not WorkflowChainOutcome.objects.filter(deployment=dep, status=oc.VIOLATED).exists()
    assert one_decision(dep, client) == Deployment.Decision.READY

    retry = client.post(url, violated, format="json")
    assert retry.status_code == 201, retry.content
    assert one_decision(dep, client) == Deployment.Decision.NOT_RECOMMENDED


@pytest.mark.django_db(transaction=True)
def test_a_reader_while_a_claim_moves_sees_one_decision(monkeypatch):
    """The claim committed, then the refresh ran in a transaction of its own. A
    reader on another connection in between saw decision-support compute the capped
    decision live under the revision the stored READY still held."""
    from assurance import views
    from assurance.claims import derive_claims

    dep = _scanned()
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).update(
        status=AssuranceClaim.ClaimStatus.SUPPORTED
    )
    recompute_decision(dep)
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).first()
    client = _client()
    seen = {}
    real = views.recompute_decision

    def reader():
        # Another thread is another connection: it sees only what has committed.
        # It reads without opening a transaction of its own. The test database
        # runs every transaction as BEGIN IMMEDIATE, as the deployed SQLite does,
        # so a reader that opened one would wait for this writer -- which is
        # waiting for the reader.
        try:
            seen["live"] = compute_decision(Deployment.objects.get(pk=dep.pk))
            seen["stored"] = Deployment.objects.values_list("decision", flat=True).get(pk=dep.pk)
        finally:
            connection.close()

    def a_reader_first(deployment, **kwargs):
        thread = threading.Thread(target=reader)
        thread.start()
        thread.join()
        return real(deployment, **kwargs)

    monkeypatch.setattr(views, "recompute_decision", a_reader_first)
    response = client.post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "contradicted"}, format="json"
    )
    assert response.status_code == 200, response.content
    assert seen == {"live": Deployment.Decision.READY, "stored": Deployment.Decision.READY}, seen
    assert one_decision(dep, client) == Deployment.Decision.NEEDS_REMEDIATION


# ------------------------------------------------ the pause decision-support publishes


def test_decision_support_reads_the_pause_from_the_row_it_reads_the_revision_from():
    """An instance loaded before the operator paused still says READY. The revision
    in the payload is the pause's, so the decision beside it must be the pause."""
    dep = _scanned()
    loaded = Deployment.objects.get(pk=dep.pk)
    assert recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True) == Deployment.Decision.PAUSED
    assert loaded.decision == Deployment.Decision.READY
    support = decision_support(loaded)
    row = Deployment.objects.values("decision", "decision_revision").get(pk=dep.pk)
    assert support["paused"] is True
    assert (support["decision"], support["revision"]) == (row["decision"], row["decision_revision"])


def test_a_pause_landing_before_the_decision_support_read_is_published_as_the_pause(monkeypatch):
    """The route read `paused` from the instance it loaded, before the transaction
    that read the revision. An operator's pause committed in between was published
    as a live READY under the revision that records the pause."""
    from assurance import views

    dep = _scanned()
    real = views.current_decision

    def then_an_operator_pauses(deployment):
        answer = real(deployment)
        # Another instance, as another request would hold: the route's own copy
        # keeps the READY it loaded.
        recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
        return answer

    monkeypatch.setattr(views, "current_decision", then_an_operator_pauses)
    support = _client().get(_base(dep) + "decision-support/").json()
    row = Deployment.objects.values("decision", "decision_revision").get(pk=dep.pk)
    assert row["decision"] == Deployment.Decision.PAUSED
    assert (support["decision"], support["revision"]) == (row["decision"], row["decision_revision"])
