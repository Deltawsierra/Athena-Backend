"""`POST /api/assurance/deployments/check/` — every stream, one consistent read.

Athena's assurance API is a set of per-deployment resources, which is right for
a dashboard asking one question at a time and wrong for anything assessing the
engine as a whole. A benchmark scoring recall across a portfolio, an export, an
auditor's snapshot — each needs the verdicts Athena currently stands behind,
across every deployment, consistently.

The bundle exists to make that answerable, and these tests pin the three things
that decide whether its answer means anything:

  * every row carries a subject, and subjects are scoped by deployment, so two
    deployments reaching the same provider are two verdicts and not one;
  * a benign reading is present and labelled rather than omitted, because a
    reader must be able to tell "assessed and fine" from "not assessed";
  * the bundle can never show a caller a deployment the deployment list would
    not, because a read-everything endpoint is exactly where a scoping mistake
    turns into a portfolio-wide leak.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import (
    Asset,
    AssuranceClaim,
    DataBoundary,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    Provider,
    ProviderAssertion,
)
from assurance.unknowns import derive_unknowns
from assurance.views import DeploymentViewSet
from tests.decision_surfaces import stamped_under_the_rules_in_force

pytestmark = pytest.mark.django_db

User = get_user_model()


def _viewer(name):
    """A non-privileged reader: analysts and admins may read the whole graph."""
    return User.objects.create_user(username=name, password="x", role=User.Roles.VIEWER)


def _admin():
    return User.objects.create_user(username="root", password="x", role=User.Roles.ADMIN)


def _provider(name, **assertions):
    provider = Provider.objects.create(name=name, kind=Provider.Kind.MODEL_PROVIDER)
    for field, value in assertions.items():
        ProviderAssertion.objects.create(
            provider=provider, field=field, value=value,
            evidence_class=EvidenceClass.VENDOR_ASSERTED,
        )
    return provider


def _bundle(user, body=None):
    request = APIRequestFactory().post("/api/assurance/deployments/check/", body or {}, format="json")
    force_authenticate(request, user=user)
    response = DeploymentViewSet.as_view({"post": "check"})(request)
    assert response.status_code == 200, response.data
    return response.data


def _subjects(bundle, stream):
    return sorted(row["subject"] for row in bundle[stream])


# ------------------------------------------------------------ the five streams


def test_every_stream_is_present_and_subject_scoped_by_deployment():
    """One request, five streams, each row named by what it accuses."""
    admin = _admin()
    provider = _provider("OpenAI EU", region="us-east-1", trains_on_data="No", subprocessors="None")
    deployment = stamped_under_the_rules_in_force(
        Deployment.objects.create(name="payments-agent", decision=Deployment.Decision.NOT_RECOMMENDED)
    )
    Asset.objects.create(
        deployment=deployment, provider=provider, kind=Asset.Kind.MODEL,
        classification=Asset.Classification.KNOWN, name="gpt-x", identifier="gpt-x",
    )
    DataBoundary.objects.create(deployment=deployment, allowed_regions=["eu-west-1"])
    Finding.objects.create(
        deployment=deployment, fingerprint="fp-drift",
        finding_type="bom_drift.undeclared_provider",
        title="Undeclared provider", severity="high", location="fallback-llm",
    )

    bundle = _bundle(admin)

    assert bundle["boundary_flows"][0]["subject"] == "payments-agent/openai-eu"
    assert bundle["boundary_flows"][0]["status"] == "violation"
    assert bundle["findings"][0]["subject"] == "payments-agent/fallback-llm"
    assert bundle["findings"][0]["finding_type"] == "bom_drift.undeclared_provider"
    assert bundle["decisions"] == [
        {"subject": "payments-agent", "state": "not_recommended", "environment": deployment.environment}
    ]
    assert bundle["deployments_assessed"] == ["payments-agent"]


def test_two_deployments_reaching_one_provider_are_two_subjects():
    """Un-scoped subjects would merge a clean flow with a violating one."""
    admin = _admin()
    provider = _provider("OpenAI", region="us-east-1", trains_on_data="No", subprocessors="None")
    for name, regions in (("payments-agent", ["eu-west-1"]), ("rag-assistant", ["us-east-1"])):
        deployment = Deployment.objects.create(name=name)
        Asset.objects.create(
            deployment=deployment, provider=provider, kind=Asset.Kind.MODEL,
            classification=Asset.Classification.KNOWN, name="m", identifier="m",
        )
        DataBoundary.objects.create(deployment=deployment, allowed_regions=regions)

    bundle = _bundle(admin)

    assert _subjects(bundle, "boundary_flows") == ["payments-agent/openai", "rag-assistant/openai"]
    by_subject = {row["subject"]: row["status"] for row in bundle["boundary_flows"]}
    assert by_subject["payments-agent/openai"] == "violation"
    assert by_subject["rag-assistant/openai"] == "approved"


def test_a_benign_reading_is_reported_rather_than_omitted():
    """'Assessed and fine' must be distinguishable from 'not assessed'."""
    admin = _admin()
    provider = _provider("Anthropic", region="eu-west-1", trains_on_data="No", subprocessors="None")
    deployment = stamped_under_the_rules_in_force(
        Deployment.objects.create(name="clean-agent", decision=Deployment.Decision.READY)
    )
    Asset.objects.create(
        deployment=deployment, provider=provider, kind=Asset.Kind.MODEL,
        classification=Asset.Classification.KNOWN, name="claude", identifier="claude",
    )
    DataBoundary.objects.create(deployment=deployment, allowed_regions=["eu-west-1"])

    bundle = _bundle(admin)

    assert [row["status"] for row in bundle["boundary_flows"]] == ["approved"]
    assert [row["state"] for row in bundle["decisions"]] == ["ready"]
    assert bundle["deployments_assessed"] == ["clean-agent"]


def test_an_empty_portfolio_is_distinguishable_from_a_clean_one():
    """Five empty streams otherwise read as 'nothing failed'."""
    bundle = _bundle(_admin())

    assert bundle["deployments_assessed"] == []
    assert bundle["boundary_flows"] == []
    assert bundle["decisions"] == []


# ------------------------------------------------------- shadow and unknowns


def test_a_shadow_destination_is_its_own_row_not_folded_into_a_flow():
    """An unmanaged sink is outside any boundary; attributing it would be a guess."""
    admin = _admin()
    deployment = Deployment.objects.create(name="rag-assistant")
    Asset.objects.create(
        deployment=deployment, provider=None, kind=Asset.Kind.DATA_STORE,
        classification=Asset.Classification.UNMANAGED, name="unmanaged sink",
        identifier="s3://unknown",
    )

    bundle = _bundle(admin)

    assert _subjects(bundle, "boundary_flows") == ["rag-assistant/unmanaged-sink"]
    assert bundle["boundary_flows"][0]["status"] == "shadow"


def test_both_kinds_of_unknown_reach_the_bundle():
    """The register's two sources, side by side, each named by its own gap."""
    admin = _admin()
    provider = _provider("OpenAI", region="eu-west-1", subprocessors="None")
    deployment = Deployment.objects.create(name="payments-agent")
    Asset.objects.create(
        deployment=deployment, provider=provider, kind=Asset.Kind.MODEL,
        classification=Asset.Classification.KNOWN, name="m", identifier="m",
    )
    DataBoundary.objects.create(deployment=deployment, allowed_regions=["eu-west-1"])
    finding = Finding.objects.create(
        deployment=deployment, fingerprint="fp-unverified",
        finding_type="prompt_injection", title="Unconfirmed", severity="high",
    )
    Evidence.objects.create(
        finding=finding, classification=EvidenceClass.UNKNOWN, source="engine_scan"
    )
    derive_unknowns(deployment)

    bundle = _bundle(admin)

    assert _subjects(bundle, "unknowns") == [
        "payments-agent/prompt-injection",
        "payments-agent/training-posture",
    ]
    by_subject = {row["subject"]: row["source"] for row in bundle["unknowns"]}
    assert by_subject["payments-agent/training-posture"] == "posture"
    assert by_subject["payments-agent/prompt-injection"] == "derived"


# ---------------------------------------------------------------------- claims


def test_only_the_current_version_of_a_claim_is_reported():
    """Carrying both versions would report one claim twice at one subject."""
    from django.utils import timezone

    admin = _admin()
    deployment = Deployment.objects.create(name="rag-assistant")
    common = dict(
        deployment=deployment, claim_type=AssuranceClaim.ClaimType.AI_BOM,
        statement="the bill of materials is complete", system_fingerprint="fp",
        policy_version="v1", environment=deployment.environment,
        evidence_class=EvidenceClass.PARTIALLY_VERIFIED, fingerprint="claim-1",
    )
    AssuranceClaim.objects.create(
        status=AssuranceClaim.ClaimStatus.SUPERSEDED, valid_to=timezone.now(), **common
    )
    AssuranceClaim.objects.create(status=AssuranceClaim.ClaimStatus.CONTRADICTED, **common)

    bundle = _bundle(admin)

    assert [row["status"] for row in bundle["claims"]] == ["contradicted"]
    assert bundle["claims"][0]["subject"] == "rag-assistant/ai_bom"


def test_a_revoked_claim_is_still_reported_as_the_current_answer():
    """The near-miss: filtering on status would drop a live claim.

    A REVOKED or STALE claim is still the current version and still what the
    engine says about that claim identity. Only a version an actual supersede
    closed is history.
    """
    admin = _admin()
    deployment = Deployment.objects.create(name="legacy-bot")
    AssuranceClaim.objects.create(
        deployment=deployment, claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY,
        statement="data stays in the EU", system_fingerprint="fp", policy_version="v1",
        environment=deployment.environment, evidence_class=EvidenceClass.PARTIALLY_VERIFIED,
        fingerprint="claim-2", status=AssuranceClaim.ClaimStatus.STALE,
    )

    bundle = _bundle(admin)
    assert [row["subject"] for row in bundle["claims"]] == ["legacy-bot/data_boundary"]
    assert bundle["claims"][0]["status"] == "stale"


# ------------------------------------------------------------------- scoping


def test_the_bundle_never_widens_what_a_caller_can_see():
    """A read-everything endpoint is where a scoping mistake becomes a leak."""
    mine = _viewer("mine")
    theirs = _viewer("theirs")
    Deployment.objects.create(name="my-agent", owner=mine)
    Deployment.objects.create(name="their-agent", owner=theirs)

    assert _bundle(mine)["deployments_assessed"] == ["my-agent"]
    assert _bundle(theirs)["deployments_assessed"] == ["their-agent"]
    assert sorted(_bundle(_admin())["deployments_assessed"]) == ["my-agent", "their-agent"]


def test_naming_a_deployment_narrows_the_portfolio():
    admin = _admin()
    Deployment.objects.create(name="payments-agent")
    Deployment.objects.create(name="rag-assistant")

    bundle = _bundle(admin, {"deployments": ["payments-agent"]})
    assert bundle["deployments_assessed"] == ["payments-agent"]


def test_naming_a_deployment_the_caller_cannot_see_returns_nothing_not_an_error():
    """The request says nothing about whether such a deployment exists."""
    mine = _viewer("mine")
    Deployment.objects.create(name="their-agent", owner=_viewer("theirs"))

    assert _bundle(mine, {"deployments": ["their-agent"]})["deployments_assessed"] == []


def test_a_malformed_deployments_filter_is_refused():
    request = APIRequestFactory().post(
        "/api/assurance/deployments/check/", {"deployments": "payments-agent"}, format="json"
    )
    force_authenticate(request, user=_admin())
    response = DeploymentViewSet.as_view({"post": "check"})(request)
    assert response.status_code == 400


def test_it_requires_authentication():
    request = APIRequestFactory().post("/api/assurance/deployments/check/", {}, format="json")
    response = DeploymentViewSet.as_view({"post": "check"})(request)
    assert response.status_code in (401, 403)


# -------------------------------------------------------------- query budget


def test_the_bundle_is_query_bounded_across_a_portfolio(django_assert_max_num_queries):
    """Cost must not grow per provider, per finding, or per claim.

    Without the prefetches, a real portfolio would issue a query per provider per
    deployment on every read — and this is the endpoint a harness calls in a
    loop.
    """
    admin = _admin()
    for index in range(5):
        deployment = Deployment.objects.create(name=f"agent-{index}")
        DataBoundary.objects.create(deployment=deployment, allowed_regions=["eu-west-1"])
        for slot in range(3):
            provider = _provider(f"vendor-{index}-{slot}", region="eu-west-1")
            Asset.objects.create(
                deployment=deployment, provider=provider, kind=Asset.Kind.MODEL,
                classification=Asset.Classification.KNOWN,
                name=f"m{slot}", identifier=f"m{slot}",
            )
        Finding.objects.create(
            deployment=deployment, fingerprint=f"fp-{index}",
            finding_type="bom_drift.undeclared_provider", title="t",
            severity="medium", location=f"comp-{index}",
        )

    with django_assert_max_num_queries(25):
        _bundle(admin)
