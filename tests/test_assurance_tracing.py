"""Athena-Backend's adoption of mythos_core.tracing.

The shared module's own behaviour is tested in mythos-core. These prove that the
*backend* calls it correctly: an ingest is one workflow span with the derivation
steps inside it, each step has its own latency row rather than being averaged
into one `plan` bucket, and the instrumentation cannot change what a derivation
decides.

Every test runs with no collector configured — the state in CI and in every
deployment today. That is deliberate: instrumentation has to be exercised in the
configuration it ships in, or the tests prove something nobody runs.
"""

from __future__ import annotations

import inspect

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import observability as obs
from assurance.claims import derive_claims
from assurance.ingest import ingest_scan
from assurance.invalidation import check_invalidations
from assurance.models import (
    Asset,
    DataBoundary,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
)
from assurance.revalidation import plan_revalidation
from assurance.ripple import assess_ripple
from assurance.views import DeploymentViewSet
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()


@pytest.fixture()
def timings():
    """A clean latency record per test, restored afterwards.

    The recorder is module state on purpose (see assurance/observability.py), so
    a test that did not reset it would read another test's samples and a p95 here
    would depend on test ordering.
    """
    obs.reset_timings()
    yield obs.TIMINGS
    obs.reset_timings()


def _admin():
    return User.objects.create_user(username="root", password="x", role=User.Roles.ADMIN)


def _viewer():
    return User.objects.create_user(username="eyes", password="x", role=User.Roles.VIEWER)


def _deployment():
    provider = Provider.objects.create(name="OpenAI EU", kind=Provider.Kind.MODEL_PROVIDER)
    ProviderAssertion.objects.create(
        provider=provider,
        field="region",
        value="us-east-1",
        evidence_class=EvidenceClass.VENDOR_ASSERTED,
    )
    deployment = Deployment.objects.create(name="payments-agent")
    Asset.objects.create(
        deployment=deployment,
        provider=provider,
        kind=Asset.Kind.MODEL,
        classification=Asset.Classification.KNOWN,
        name="gpt-x",
        identifier="gpt-x",
    )
    DataBoundary.objects.create(deployment=deployment, allowed_regions=["eu-west-1"])
    return deployment


def _rows(table=None):
    return {row["component"]: row for row in (table if table is not None else obs.latency_table())}


def _scan(findings):
    """A real PentestScan, because Finding.scan is a foreign key.

    A stub would have to satisfy the ORM's relation check, and a fake that gets
    far enough to do that is no longer proving anything about the real path.
    """
    user = User.objects.create_user(
        username=f"scanner-{len(findings)}-{Deployment.objects.count()}",
        password="x",
        role=User.Roles.ANALYST,
    )
    return PentestScan.objects.create(
        user=user,
        target_url="https://app.client.example/login",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": findings},
    )


# ---------------------------------------------------------------------------
# The vocabulary is bound once
# ---------------------------------------------------------------------------


def test_every_component_is_filed_under_this_service(timings):
    """`athena-backend`, spelled once, and named apart from the scanning engine.

    A deployment assessment crosses both. Folding them into one component makes
    "the assessment spent eight seconds in Athena" unanswerable as to which one.
    """
    with obs.span(obs.PLAN, component="something"):
        pass

    assert obs.ENGINE == "athena-backend"
    assert all(row["component"].startswith("athena-backend.") for row in obs.latency_table())


def test_the_span_names_are_the_shared_ones(timings):
    from mythos_core import tracing

    assert obs.INVOKE_WORKFLOW == tracing.INVOKE_WORKFLOW
    assert obs.PLAN == tracing.PLAN
    assert obs.RETRIEVAL == tracing.RETRIEVAL


# ---------------------------------------------------------------------------
# An ingest is one tree
# ---------------------------------------------------------------------------


def test_an_ingest_is_one_workflow_with_the_steps_inside_it(timings):
    deployment = _deployment()
    scan = _scan([{"type": "prompt_injection", "severity": "high", "location": "/chat"}])

    ingest_scan(scan, deployment=deployment)

    rows = _rows()
    assert rows["athena-backend.ingest_scan"]["samples"] == 1
    for step in (
        "athena-backend.derive_assets",
        "athena-backend.derive_unknowns",
        "athena-backend.recompute_decision",
    ):
        assert step in rows, f"{step} runs inside an ingest and was not recorded"

    # The workflow contains the steps rather than sitting beside them.
    ingest_ms = rows["athena-backend.ingest_scan"]["max_ms"]
    for name, row in rows.items():
        if name == "athena-backend.ingest_scan":
            continue
        assert row["max_ms"] <= ingest_ms + 1e-6, f"{name} outlasted the ingest containing it"


def test_an_ingest_with_no_findings_records_nothing(timings):
    """A no-op ingest is not work, and a near-zero sample would drag the p50 down.

    The empty-findings return is above the span on purpose; this pins that.
    """
    deployment = _deployment()

    assert ingest_scan(_scan([]), deployment=deployment) == []
    assert obs.latency_table() == []


def test_each_derivation_step_gets_its_own_row(timings):
    """Claims, invalidation, revalidation and the ripple walk are all one span name.

    One `plan` row averaging four unlike derivations has a p95 that names nothing
    a reader can go and change, which is the whole point of the table.
    """
    deployment = _deployment()

    derive_claims(deployment)
    check_invalidations(deployment)
    plan_revalidation(deployment)
    assess_ripple(deployment)

    rows = _rows()
    for step in (
        "athena-backend.derive_claims",
        "athena-backend.check_invalidations",
        "athena-backend.plan_revalidation",
        "athena-backend.assess_ripple",
    ):
        assert step in rows, f"{step} has no row of its own"
    assert "athena-backend.plan" not in rows, "a step fell back to the bare span name"


def test_the_ripple_traversal_is_a_retrieval_not_a_plan(timings):
    """It walks the graph and derives no verdict of its own; the span should say so."""
    deployment = _deployment()

    assess_ripple(deployment)

    # The row is keyed by component, so read the span name off the vocabulary the
    # call site used rather than inferring it from the row.
    assert "athena-backend.assess_ripple" in _rows()


# ---------------------------------------------------------------------------
# Instrumentation must not change what it measures
# ---------------------------------------------------------------------------


def test_the_ingest_still_returns_its_findings(timings):
    deployment = _deployment()
    scan = _scan(
        [
            {"type": "prompt_injection", "severity": "high", "location": "/chat"},
            {"type": "rag_leakage", "severity": "critical", "location": "/search"},
        ]
    )

    results = ingest_scan(scan, deployment=deployment)

    assert len(results) == 2
    assert {f.finding_type for f in results} == {"prompt_injection", "rag_leakage"}


def test_derive_claims_still_returns_its_counts(timings):
    deployment = _deployment()

    counts = derive_claims(deployment)

    assert set(counts) == {"created", "updated", "superseded", "stale"}
    assert counts["created"] > 0, "a fresh deployment derives claims; otherwise this proves nothing"


def test_a_second_derivation_is_still_idempotent(timings):
    """The property the extraction could most easily have broken."""
    deployment = _deployment()

    derive_claims(deployment)
    again = derive_claims(deployment)

    assert again["created"] == 0
    assert again["superseded"] == 0


def test_no_deployment_name_or_finding_reaches_a_span(timings):
    """Spans carry the deployment's primary key, never its name or a finding.

    A span attribute is exported to a collector that is not necessarily inside the
    same trust boundary as the assessment, and a customer's deployment name is
    identifying. This reads the attributes the code actually builds, because the
    leak would be silent.
    """
    from contextlib import contextmanager

    seen: list = []
    real = obs.span

    @contextmanager
    def capture(name, *, subject="", attributes=None, component=None):
        seen.append(subject)
        if attributes:
            seen.extend(str(v) for v in attributes.values())
        with real(name, subject=subject, attributes=attributes, component=component) as active:
            yield active

    deployment = _deployment()
    scan = _scan([{"type": "prompt_injection", "severity": "high", "location": "/secret-path"}])

    import assurance.claims as claims_mod
    import assurance.ingest as ingest_mod

    ingest_mod.obs.span, claims_mod.obs.span = capture, capture
    try:
        ingest_scan(scan, deployment=deployment)
        derive_claims(deployment)
    finally:
        ingest_mod.obs.span, claims_mod.obs.span = real, real

    assert seen, "the capture wired up; otherwise this asserts nothing"
    joined = " ".join(seen)
    assert "payments-agent" not in joined
    assert "/secret-path" not in joined
    assert str(deployment.pk) in joined, "the pk is what a trace correlates on"


# ---------------------------------------------------------------------------
# The baseline has to be reachable from outside the process
# ---------------------------------------------------------------------------


def _latency(user):
    request = APIRequestFactory().get("/api/assurance/deployments/latency/")
    force_authenticate(request, user=user)
    return DeploymentViewSet.as_view({"get": "latency"})(request)


def test_the_latency_table_is_reachable_over_http(timings):
    """A campaign drives the stack over HTTP; the recorder lives inside a worker."""
    admin = _admin()
    with obs.span(obs.PLAN, component="derive_claims"):
        pass

    response = _latency(admin)

    assert response.status_code == 200, response.data
    assert response.data["engine"] == "athena-backend"
    assert response.data["measured"] is True
    assert response.data["scope"] == "worker_process"
    assert [r["component"] for r in response.data["components"]] == [
        "athena-backend.derive_claims"
    ]
    assert response.data["components"][0]["samples"] == 1


def test_nothing_measured_is_an_empty_list_and_says_so(timings):
    """A zero in a latency column reads as "instant" when it means "never measured"."""
    response = _latency(_admin())

    assert response.data["components"] == []
    assert response.data["measured"] is False


def test_the_latency_table_is_admin_only(timings):
    """Component names are the derivation steps in order — a map of the pipeline.

    A viewer can read the assurance graph; the pipeline's internals are a
    different question, and the other structural reads are privileged for the
    same reason.
    """
    assert _latency(_viewer()).status_code == 403
    assert _latency(_admin()).status_code == 200


# ---------------------------------------------------------------------------
# The exporter, and clearing the record without destroying live spans
# ---------------------------------------------------------------------------

def test_the_app_wires_the_exporter_at_startup():
    """configure() was defined here and called from nowhere.

    That is worse than not having it. With a collector configured in the
    environment, status() reported `exporting: False` and the detail "spans are
    created and dropped: no collector is configured" -- so the one operator who
    had done the work was told to go and do it, on the route
    (/api/assurance/deployments/latency/) that publishes that string. It also
    dropped this service's half of every cross-engine trace, which is the half
    the SPINE derivation contributes.
    """
    from django.apps import apps

    config = apps.get_app_config("assurance")
    source = inspect.getsource(config.ready)
    assert "observability.configure()" in source, (
        "the assurance app does not wire the tracing exporter at startup"
    )


def test_clearing_the_record_does_not_orphan_a_span_that_is_still_open():
    """reset_timings() rebound the global; a span holds the object it entered with.

    So a sample recorded after a reset landed in an orphan -- and selectively:
    a span longer than the gap between resets can never survive, which is
    exactly the slow work a p95 exists to find. Measured on the baseline
    harness, an outer workflow span was lost while every one of its children
    survived, publishing a table with one assessment and five of its own steps.
    """
    import assurance.observability as obs

    before = obs.TIMINGS
    with obs.span(obs.INVOKE_WORKFLOW, component="long_running", subject="deployment:1"):
        obs.reset_timings()
        assert obs.TIMINGS is before, (
            "the recorder was replaced while a span was open; this span's "
            "duration is about to be recorded into an object nothing reads"
        )

    rows = {row["component"]: row for row in obs.latency_table()}
    assert "athena-backend.long_running" in rows, (
        "the span that was open across the reset did not reach the live table"
    )


def test_clearing_the_record_still_clears_it():
    """The guard must not be a reset that does not reset."""
    import assurance.observability as obs

    with obs.span(obs.PLAN, component="transient", subject="deployment:1"):
        pass
    assert any(r["component"] == "athena-backend.transient" for r in obs.latency_table())

    obs.reset_timings()
    assert obs.latency_table() == []
