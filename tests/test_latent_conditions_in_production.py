"""Phase 2 items 9 and 6, as the running system does them -- not as a test calls them.

Both modules were correct and neither was reachable. Nothing outside the tests called
:func:`assurance.latent.evaluate_conditions`, so a declared precondition that came
true fired never: the claim stayed a pass and no retest opened. Nothing could declare
one either. And a re-derive left both halves behind on the version it closed: the
watches, which nothing evaluates on a closed version while the posture counted them
watched, and the claim's legal ruling, which the new version came back without.

Each test here drives the path production takes -- a scan ingest, an API write, a
write the admin makes that commits -- and changes only the named condition.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import ingest, latent
from assurance.claims import derive_claims
from assurance.decision import claim_decision_signal, decision_support, recompute_decision
from assurance.latent import declare_condition, fire_due_conditions, latent_posture
from assurance.models import (
    Asset,
    AssuranceClaim,
    DataBoundary,
    Deployment,
    EvidenceClass,
    LatentCondition,
    LegalStatus,
    Provider,
    ProviderAssertion,
    RetestRequirement,
)
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
Kind = LatentCondition.Kind
State = LatentCondition.State
Status = AssuranceClaim.ClaimStatus


def _user(role=None):
    return User.objects.create_user(
        username=f"u{User.objects.count()}", password="x", role=role or User.Roles.ADMIN
    )


def _client(user=None):
    client = APIClient()
    client.force_authenticate(user=user or _user())
    return client


def _ready():
    """A deployment a complete scan found nothing on, its claims derived and passing:
    READY, stored and current."""
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_user())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False, third_party_sharing_allowed=False
    )
    derive_claims(dep)
    AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).update(status=Status.SUPPORTED)
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.READY
    return dep


def _claim(dep, claim_type=None):
    claims = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
    if claim_type is not None:
        claims = claims.filter(claim_type=claim_type)
    return claims.order_by("pk").first()


def _declare(claim, **condition):
    condition.setdefault("description", "the declared precondition")
    return declare_condition(claim, **condition)


# ---------------------------------------------------------------------------
# It fires, where production changes the named thing
# ---------------------------------------------------------------------------


def _scan(dep, tools):
    return PentestScan.objects.create(
        user=dep.owner, target_url="https://a.example/bot", consent=True,
        status=PentestScan.STATUS_COMPLETED, engine_response={"findings": []},
        target_config={"agent": {"name": "assistant"}, "tools": tools},
    )


def test_a_scan_that_grants_the_named_capability_fires_the_condition_it_names():
    """The roadmap's own example, through the path a real deployment takes: the next
    scan gives the assistant a way to run code, and the claim that was safe only
    because it had none goes stale with a retest that says so."""
    dep = _ready()
    ingest.ingest_scan(_scan(dep, [{"name": "reader", "permissions": ["read"]}]), deployment=dep)
    claim = _claim(dep)
    condition = _declare(
        claim, kind=Kind.PRINCIPAL_GAINS_CAPABILITY, subject="assistant", expected="code_execution",
        description="contained only while the assistant cannot run code",
    )

    ingest.ingest_scan(
        _scan(dep, [{"name": "reader", "permissions": ["read"]}, {"name": "shell", "permissions": ["exec"]}]),
        deployment=dep,
    )

    condition.refresh_from_db()
    claim.refresh_from_db()
    assert condition.state == State.FIRED
    assert claim.status == Status.STALE
    requirement = RetestRequirement.objects.get(deployment=dep, claim=claim, resolved_at__isnull=True)
    assert "contained only while the assistant cannot run code" in requirement.reason


def test_a_boundary_write_that_makes_a_declared_condition_true_fires_it_in_that_write():
    dep = _ready()
    claim = _claim(dep)
    client = _client()
    declared = client.post(
        f"/api/assurance/claims/{claim.uuid}/latent-conditions/",
        {"kind": Kind.BOUNDARY_ALLOWS, "subject": "training", "description": "training stays denied"},
        format="json",
    )
    assert declared.status_code == 201, declared.content
    assert declared.json()["state"] == State.PENDING

    written = client.patch(f"/api/assurance/deployments/{dep.uuid}/data-boundary/", {"training_allowed": True}, format="json")

    assert written.status_code == 200, written.content
    claim.refresh_from_db()
    dep.refresh_from_db()
    assert LatentCondition.objects.get(claim=claim).state == State.FIRED
    assert claim.status == Status.STALE
    assert dep.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert "training stays denied" in RetestRequirement.objects.get(deployment=dep, resolved_at__isnull=True).reason


@pytest.mark.parametrize("appears", [True, False], ids=["the-asset-appears", "nothing-appears"])
def test_a_write_the_admin_or_a_shell_makes_fires_the_condition_when_it_commits(
    django_capture_on_commit_callbacks, appears
):
    """No route refreshes after an ORM write; the backstop does, once per deployment
    per transaction, when it commits. The whole transaction is captured, as one
    commit is in production: its refresh was scheduled by the first input it wrote."""
    with django_capture_on_commit_callbacks(execute=True):
        dep = _ready()
        condition = _declare(_claim(dep), kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
        if appears:
            Asset.objects.create(
                deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
                classification=Asset.Classification.KNOWN,
            )

    condition.refresh_from_db()
    dep.refresh_from_db()
    assert condition.state == (State.FIRED if appears else State.PENDING)
    assert (dep.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE) is appears


def test_the_invalidation_check_fires_declared_conditions_too():
    dep = _ready()
    _declare(_claim(dep), kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )

    counts = _client().post(f"/api/assurance/deployments/{dep.uuid}/check-invalidations/").json()

    assert counts["conditions_fired"] == 1


def test_a_condition_that_cannot_be_evaluated_never_blocks_the_write_it_follows(monkeypatch, caplog):
    """It runs inside writes that must not fail for it -- a person revoking a claim
    among them. The failure is logged and the condition keeps its last evaluation."""
    dep = _ready()
    claim = _claim(dep)
    condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    def broken(*args, **kwargs):
        raise RuntimeError("the observer broke")

    monkeypatch.setattr(latent, "evaluate_conditions", broken)
    revoked = _client().post(f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "revoked"}, format="json")

    assert revoked.status_code == 200, revoked.content
    claim.refresh_from_db()
    condition.refresh_from_db()
    assert claim.status == Status.REVOKED
    assert condition.state == State.PENDING
    assert "were not evaluated" in caplog.text


# ---------------------------------------------------------------------------
# A re-derive carries the watch and the ruling; the posture counts what is watched
# ---------------------------------------------------------------------------


def test_a_re_derive_carries_the_watch_to_the_claims_new_version():
    dep = _ready()
    claim = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    condition = _declare(claim, kind=Kind.BOUNDARY_REGION_ADDED, subject="boundary", expected="us-east-1")

    DataBoundary.objects.filter(deployment=dep).update(allowed_regions=["eu-west-1", "eu-central-1"])
    derive_claims(Deployment.objects.get(pk=dep.pk))

    claim.refresh_from_db()
    condition.refresh_from_db()
    assert claim.valid_to is not None
    assert condition.claim.valid_to is None and condition.claim_id != claim.pk
    posture = latent_posture(dep)
    assert (posture["watching"], posture["unwatched"]) == (1, 0)

    DataBoundary.objects.filter(deployment=dep).update(allowed_regions=["eu-west-1", "us-east-1"])
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1


def test_a_watch_on_a_claim_nothing_evaluates_is_not_counted_as_watching():
    dep = _ready()
    claim = _claim(dep)
    _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=Status.REVOKED)

    posture = latent_posture(dep)

    assert (posture["watching"], posture["unwatched"]) == (0, 1)
    assert "unwatched" in posture["note"]


def test_a_re_derive_keeps_the_legal_ruling_a_person_recorded():
    dep = _ready()
    claim = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    AssuranceClaim.objects.filter(pk=claim.pk).update(legal_status=LegalStatus.STALE)

    DataBoundary.objects.filter(deployment=dep).update(allowed_regions=["eu-west-1", "eu-central-1"])
    derive_claims(Deployment.objects.get(pk=dep.pk))

    claim.refresh_from_db()
    current = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    assert claim.valid_to is not None and current.pk != claim.pk
    assert current.legal_status == LegalStatus.STALE


def test_a_claim_a_person_judged_legally_stale_caps_the_decision_and_a_pending_review_does_not():
    dep = _ready()
    claim = _claim(dep)

    AssuranceClaim.objects.filter(pk=claim.pk).update(legal_status=LegalStatus.REVIEW_PENDING)
    assert claim_decision_signal(dep)["cap"] is None

    AssuranceClaim.objects.filter(pk=claim.pk).update(legal_status=LegalStatus.STALE)
    signal = claim_decision_signal(dep)
    assert signal["cap"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [c.pk for c in signal["legally_stale"]] == [claim.pk]
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE
    support = decision_support(dep)
    assert "legally stale" in support["note"]
    assert len(support["claims"]["legally_stale"]) == 1


def test_0037_brings_a_left_behind_watch_and_ruling_to_the_current_version():
    from importlib import import_module

    from django.apps import apps

    migration = import_module("assurance.migrations.0037_carry_watches_and_legal_rulings")
    dep = _ready()
    old = _claim(dep)
    condition = _declare(old, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    # A re-derive as it went before: a new version, and nothing carried to it.
    AssuranceClaim.objects.filter(pk=old.pk).update(
        legal_status=LegalStatus.STALE, valid_to=timezone.now(), status=Status.SUPERSEDED
    )
    new = AssuranceClaim.objects.create(
        deployment=dep, claim_type=old.claim_type, statement=old.statement, fingerprint=old.fingerprint,
        system_fingerprint="moved", policy_version=old.policy_version, environment=dep.environment,
        status=Status.SUPPORTED,
    )
    AssuranceClaim.objects.filter(pk=old.pk).update(superseded_by=new)

    for _ in range(2):  # the second pass changes nothing
        migration.carry_forward(apps, None)
        condition.refresh_from_db()
        new.refresh_from_db()
        assert condition.claim_id == new.pk
        assert new.legal_status == LegalStatus.STALE


# ---------------------------------------------------------------------------
# The API: declared by an admin, refused where it would lie, withdrawn visibly
# ---------------------------------------------------------------------------


def test_declaring_refuses_a_condition_that_already_holds_and_one_on_a_closed_version():
    dep = _ready()
    claim = _claim(dep)
    client = _client()
    url = f"/api/assurance/claims/{claim.uuid}/latent-conditions/"

    holds = client.post(
        url, {"kind": Kind.BOUNDARY_REGION_ADDED, "subject": "boundary", "expected": "eu-west-1",
              "description": "no EU region"}, format="json",
    )
    assert holds.status_code == 400 and "already holds" in holds.json()["detail"]

    AssuranceClaim.objects.filter(pk=claim.pk).update(valid_to=timezone.now())
    closed = client.post(url, {"kind": Kind.ASSET_APPEARS, "subject": "x", "description": "y"}, format="json")
    assert closed.status_code == 400 and "current, unrevoked version" in closed.json()["detail"]
    assert not LatentCondition.objects.exists()


def test_only_an_admin_declares_or_withdraws_and_anyone_with_the_deployment_reads():
    dep = _ready()
    claim = _claim(dep)
    condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    analyst = _client(_user(User.Roles.ANALYST))

    assert analyst.post(
        f"/api/assurance/claims/{claim.uuid}/latent-conditions/",
        {"kind": Kind.ASSET_APPEARS, "subject": "x", "description": "y"}, format="json",
    ).status_code == 403
    assert analyst.post(
        f"/api/assurance/claims/{claim.uuid}/latent-conditions/{condition.uuid}/withdraw/", {}, format="json"
    ).status_code == 403
    posture = _client().get(f"/api/assurance/deployments/{dep.uuid}/latent-conditions/").json()
    assert posture["watching"] == 1 and posture["conditions"][0]["uuid"] == str(condition.uuid)


def test_a_withdrawn_condition_is_kept_and_a_fired_one_cannot_be_withdrawn():
    dep = _ready()
    claim = _claim(dep)
    client = _client()
    kept = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    fired = _declare(claim, kind=Kind.ASSET_APPEARS, subject="second-exporter")
    LatentCondition.objects.filter(pk=fired.pk).update(state=State.FIRED, fired_observation="it appeared")

    out = client.post(
        f"/api/assurance/claims/{claim.uuid}/latent-conditions/{kept.uuid}/withdraw/", {"note": "fixed"}, format="json"
    )
    assert out.status_code == 200 and out.json()["state"] == State.WITHDRAWN
    assert LatentCondition.objects.filter(pk=kept.pk).exists()

    refused = client.post(
        f"/api/assurance/claims/{claim.uuid}/latent-conditions/{fired.uuid}/withdraw/", {"note": "x"}, format="json"
    )
    assert refused.status_code == 409
    fired.refresh_from_db()
    assert (fired.state, fired.fired_observation) == (State.FIRED, "it appeared")


def test_a_posture_condition_on_a_name_two_providers_share_is_unobservable_not_a_guess():
    """A provider name is unique only within a kind, and the reading was taken off
    whichever of them the database returned first."""
    dep = _ready()
    provider = Provider.objects.create(name="OpenAI", kind=Provider.Kind.MODEL_PROVIDER)
    ProviderAssertion.objects.create(
        provider=provider, field="region", value="eu", evidence_class=EvidenceClass.VENDOR_ASSERTED
    )
    condition = _declare(_claim(dep), kind=Kind.PROVIDER_POSTURE_CHANGES, subject="OpenAI", expected="region")
    other = next(k for k in Provider.Kind.values if k != Provider.Kind.MODEL_PROVIDER)
    Provider.objects.create(name="OpenAI", kind=other)

    latent.evaluate_conditions(dep)

    condition.refresh_from_db()
    assert condition.state == State.UNOBSERVABLE
