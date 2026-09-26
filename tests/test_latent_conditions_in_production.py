"""Phase 2 items 9 and 6, as the running system does them -- not as a test calls them.

Both modules were correct and neither was reachable. Nothing outside the tests called
:func:`assurance.latent.evaluate_conditions`, so a declared precondition that came
true fired never: the claim stayed a pass and no retest opened. Nothing could declare
one either. And a re-derive left both halves behind on the version it closed: the
watches, which nothing evaluates on a closed version while the posture counted them
watched, and the claim's legal ruling, which the new version came back without.

Each test here drives the path production takes -- a scan ingest, an API write, a
write the admin makes that commits -- and changes only the named condition.

And the round after: evaluation ran inside a claim revoke and delayed it; a
re-derive read a claim a fired condition had marked straight back to a pass; a
condition that lost sight of its subject once was never read again; one observer
that raised rolled back every other condition's evaluation; 0037 aborted on a watch
already carried; a provider write evaluated every deployment watching it inside its
own transaction; and two conditions firing on one claim marked it stale twice.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import ingest, latent, signals
from assurance.claims import apply_claim_transition, derive_claims
from assurance.decision import claim_decision_signal, decision_support, recompute_decision
from assurance.latent import declare_condition, fire_due_conditions, latent_posture
from assurance.models import (
    LATENT_LIVE_STATES,
    Asset,
    AssuranceClaim,
    ClaimEvent,
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


def test_a_condition_that_cannot_be_evaluated_never_blocks_the_write_it_follows(
    monkeypatch, caplog, django_capture_on_commit_callbacks
):
    """It is evaluated once the write it follows has committed -- a person revoking a
    claim among them -- never inside it. A failure there is logged, the write stands,
    and the condition keeps its last evaluation."""
    with django_capture_on_commit_callbacks(execute=True):  # the set-up commits
        dep = _ready()
        claim = _claim(dep)
        condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    def broken(*args, **kwargs):
        raise RuntimeError("the observer broke")

    monkeypatch.setattr(latent, "evaluate_conditions", broken)
    with django_capture_on_commit_callbacks(execute=True):
        revoked = _client().post(
            f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "revoked"}, format="json"
        )

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


def test_a_withdrawn_condition_is_kept_and_a_fired_one_is_withdrawn_only_with_a_reason():
    """A fired condition holds its claim until a person withdraws it, which accepts
    the state it fired on: so it can be withdrawn -- it used to answer 409 -- but only
    with a reason, recorded with who gave it, and never over what it observed."""
    dep = _ready()
    claim = _claim(dep)
    admin = _user()
    client = _client(admin)
    kept = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    fired = _declare(claim, kind=Kind.ASSET_APPEARS, subject="second-exporter")
    LatentCondition.objects.filter(pk=fired.pk).update(state=State.FIRED, fired_observation="it appeared")
    url = f"/api/assurance/claims/{claim.uuid}/latent-conditions/"

    out = client.post(f"{url}{kept.uuid}/withdraw/", {"note": "fixed"}, format="json")
    assert out.status_code == 200 and out.json()["state"] == State.WITHDRAWN
    assert LatentCondition.objects.filter(pk=kept.pk).exists()

    unexplained = client.post(f"{url}{fired.uuid}/withdraw/", {"note": "  "}, format="json")
    assert unexplained.status_code == 400 and "note" in unexplained.json()["detail"]
    fired.refresh_from_db()
    assert fired.state == State.FIRED

    accepted = client.post(f"{url}{fired.uuid}/withdraw/", {"note": "the exporter is ours"}, format="json")
    assert accepted.status_code == 200, accepted.content
    fired.refresh_from_db()
    assert (fired.state, fired.fired_observation) == (State.WITHDRAWN, "it appeared")
    assert (fired.withdrawn_by, fired.withdrawn_note) == (admin, "the exporter is ours")
    assert fired.withdrawn_at is not None
    assert accepted.json()["withdrawn_by"] == admin.username

    assert client.post(f"{url}{fired.uuid}/withdraw/", {"note": "again"}, format="json").status_code == 409


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


# ---------------------------------------------------------------------------
# Nothing that watches runs inside a stop
# ---------------------------------------------------------------------------


def _counting_observations(monkeypatch) -> list:
    """Every condition :func:`assurance.latent.observe` reads from here on, by pk."""
    observed = []
    real = latent.observe

    def counting(condition, deployment):
        observed.append(condition.pk)
        return real(condition, deployment)

    monkeypatch.setattr(latent, "observe", counting)
    return observed


def test_a_revoke_evaluates_no_condition_before_it_commits(monkeypatch, django_capture_on_commit_callbacks):
    """A revoke is a stop, and nothing that watches may delay one. It evaluated every
    condition on the deployment inline, before it could commit -- 2.3 seconds with a
    hundred principal conditions over three hundred tools. Now the revoke recomputes
    the decision and returns, and the conditions are read once it has committed."""
    with django_capture_on_commit_callbacks(execute=True):  # the set-up commits
        dep = _ready()
        target = _claim(dep, AssuranceClaim.ClaimType.AI_BOM)
        other = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
        conditions = [_declare(other, kind=Kind.ASSET_APPEARS, subject=f"exporter-{i}") for i in range(5)]
        # The claim revoked is what holds the decision back, so the revoke moves it.
        AssuranceClaim.objects.filter(pk=target.pk).update(status=Status.STALE)
        recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE
    observed = _counting_observations(monkeypatch)

    with django_capture_on_commit_callbacks() as hooks:
        revoked = _client().post(
            f"/api/assurance/claims/{target.uuid}/transition/", {"to_status": "revoked"}, format="json"
        )
        assert revoked.status_code == 200, revoked.content
        assert observed == [], "a condition was evaluated inside the revoke"
        dep.refresh_from_db()
        assert dep.decision == Deployment.Decision.READY, "the decision is still recomputed in the revoke"

    assert any(isinstance(h, signals._RefreshAfterCommit) and h.deployment_id == dep.pk for h in hooks)
    for hook in hooks:  # the revoke commits
        hook()
    assert sorted(set(observed)) == sorted(c.pk for c in conditions)


def test_a_pause_evaluates_no_condition_before_or_after_it_commits(monkeypatch, django_capture_on_commit_callbacks):
    with django_capture_on_commit_callbacks(execute=True):
        dep = _ready()
        _declare(_claim(dep), kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    observed = _counting_observations(monkeypatch)

    with django_capture_on_commit_callbacks(execute=True):
        paused = _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")

    assert paused.status_code == 200, paused.content
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.PAUSED
    assert observed == []


def test_one_evaluation_reads_the_effective_access_once_however_many_principal_conditions(monkeypatch):
    """Each principal condition assessed the whole deployment's effective access
    afresh; one evaluation now reads it once and every principal condition shares it."""
    from assurance import access

    dep = _ready()
    ingest.ingest_scan(_scan(dep, [{"name": "reader", "permissions": ["read"]}]), deployment=dep)
    claim = _claim(dep)
    for i in range(5):
        _declare(claim, kind=Kind.PRINCIPAL_GAINS_CAPABILITY, subject="assistant", expected=f"cap_{i}")
    _declare(claim, kind=Kind.PRINCIPAL_BECOMES_PRIVILEGED, subject="assistant")
    assessed = []
    real = access.assess_effective_access

    def counting(deployment):
        assessed.append(deployment.pk)
        return real(deployment)

    monkeypatch.setattr(access, "assess_effective_access", counting)

    result = latent.evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert result["still_pending_count"] == 6
    assert assessed == [dep.pk]


# ---------------------------------------------------------------------------
# A fired condition holds its claim until it re-arms or a person withdraws it
# ---------------------------------------------------------------------------


def _derived_ready():
    """A deployment whose claims DERIVE to a pass -- no status forced -- so a
    re-derive reads them as a pass as well: READY, stored and current."""
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_user())
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False, third_party_sharing_allowed=False
    )
    ingest.ingest_scan(_scan(dep, [{"name": "reader", "permissions": ["read"]}]), deployment=dep)
    provider, _ = Provider.objects.get_or_create(name="OpenAI", kind=Provider.Kind.MODEL_PROVIDER)
    for field, value in (("region", "eu-west-1"), ("trains_on_data", "No"), ("subprocessors", "none"), ("shares_data", "No")):
        ProviderAssertion.objects.get_or_create(
            provider=provider, field=field,
            defaults={"value": value, "evidence_class": EvidenceClass.CONFIGURATION_VERIFIED},
        )
    Asset.objects.filter(deployment=dep, kind=Asset.Kind.MODEL).update(provider=provider, metadata={"region": "eu-west-1"})
    if not Asset.objects.filter(deployment=dep, kind=Asset.Kind.MODEL).exists():
        Asset.objects.create(
            deployment=dep, provider=provider, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt",
            classification=Asset.Classification.KNOWN, metadata={"region": "eu-west-1"},
        )
    Asset.objects.filter(deployment=dep).update(assessed_at=timezone.now())
    dep = Deployment.objects.get(pk=dep.pk)
    derive_claims(dep)
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.READY, dep.decision
    return dep


def _training_watched(dep):
    """The boundary claim, and a condition on it that training stays denied."""
    claim = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    condition = _declare(
        claim, kind=Kind.BOUNDARY_ALLOWS, subject="training", description="safe only while training stays denied"
    )
    return claim, condition


def _allow_training(client, dep, allowed=True):
    response = client.patch(
        f"/api/assurance/deployments/{dep.uuid}/data-boundary/", {"training_allowed": allowed}, format="json"
    )
    assert response.status_code == 200, response.content


def _re_derive(client, dep):
    response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/")
    assert response.status_code == 200, response.content
    return response.json()


def test_a_re_derive_does_not_read_a_claim_a_fired_condition_holds_back_to_a_pass():
    """The claim went STALE and a retest opened; a routine re-derive refreshed it
    straight back to VERIFIED, resolved the retest, and the deployment read READY
    while training -- the thing it was safe only without -- stayed allowed."""
    dep = _derived_ready()
    client = _client()
    _claim_before, condition = _training_watched(dep)
    _allow_training(client, dep)
    condition.refresh_from_db()
    assert condition.state == State.FIRED
    requirement = RetestRequirement.objects.get(deployment=dep, resolved_at__isnull=True)

    # The first supersedes the claim (its boundary moved); the second refreshes it in place.
    for counts in (_re_derive(client, dep), _re_derive(client, dep)):
        current = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
        condition.refresh_from_db()
        requirement.refresh_from_db()
        dep.refresh_from_db()
        assert current.status == Status.STALE, counts
        assert (condition.state, condition.claim_id) == (State.FIRED, current.pk)
        assert requirement.resolved_at is None
        assert dep.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE
        # Read exactly as any STALE claim is: in the stale bucket, capping the decision.
        support = decision_support(dep)
        assert support["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
        assert [c["uuid"] for c in support["claims"]["stale"]] == [str(current.uuid)]
        assert "stale or unproven claim" in support["note"]


def test_a_re_derive_that_refreshes_the_claim_in_place_keeps_the_hold_too():
    dep = _derived_ready()
    vendor = Provider.objects.create(name="VendorX", kind=Provider.Kind.MODEL_PROVIDER)
    retention = ProviderAssertion.objects.create(
        provider=vendor, field="data_retention", value="0d", evidence_class=EvidenceClass.VENDOR_ASSERTED
    )
    claim = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    _declare(claim, kind=Kind.PROVIDER_POSTURE_CHANGES, subject="VendorX", expected="data_retention")
    ProviderAssertion.objects.filter(pk=retention.pk).update(value="365d")
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1

    counts = derive_claims(Deployment.objects.get(pk=dep.pk))

    assert counts["superseded"] == 0
    claim.refresh_from_db()
    assert claim.status == Status.STALE
    assert RetestRequirement.objects.filter(deployment=dep, claim=claim, resolved_at__isnull=True).exists()
    assert recompute_decision(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_fired_condition_found_back_at_its_baseline_re_arms_and_resolves_its_retest():
    dep = _derived_ready()
    client = _client()
    _claim_before, condition = _training_watched(dep)
    _allow_training(client, dep)
    requirement = RetestRequirement.objects.get(deployment=dep, resolved_at__isnull=True)

    _allow_training(client, dep, allowed=False)

    condition.refresh_from_db()
    requirement.refresh_from_db()
    assert condition.state == State.PENDING
    assert condition.fired_observation.startswith("Re-armed")
    assert requirement.resolved_at is not None
    # The claim reads its own derivation again at the next re-derive.
    _re_derive(client, dep)
    assert _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY).status == Status.VERIFIED
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.READY
    # And the watch is armed again.
    _allow_training(client, dep)
    condition.refresh_from_db()
    assert condition.state == State.FIRED


def test_withdrawing_a_fired_condition_accepts_the_new_state_and_its_retest_resolves_as_usual():
    dep = _derived_ready()
    client = _client()
    claim, condition = _training_watched(dep)
    _allow_training(client, dep)
    _re_derive(client, dep)
    requirement = RetestRequirement.objects.get(deployment=dep, resolved_at__isnull=True)
    current = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    assert current.status == Status.STALE

    withdrawn = client.post(
        f"/api/assurance/claims/{current.uuid}/latent-conditions/{condition.uuid}/withdraw/",
        {"note": "training on this data is approved now"},
        format="json",
    )

    assert withdrawn.status_code == 200, withdrawn.content
    condition.refresh_from_db()
    assert condition.state == State.WITHDRAWN
    assert condition.withdrawn_note == "training on this data is approved now"
    assert "training_allowed=True" in condition.fired_observation
    _re_derive(client, dep)
    requirement.refresh_from_db()
    dep.refresh_from_db()
    assert _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY).status == Status.VERIFIED
    assert requirement.resolved_at is not None
    assert dep.decision == Deployment.Decision.READY


def test_a_fired_condition_still_holding_puts_back_the_hold_something_removed():
    """A person moved the claim back to a pass, and a re-derive from before this rule
    resolved the retest: the next evaluation finds the condition still true, marks
    the claim STALE again and opens a retest, since nobody withdrew it."""
    dep = _ready()
    claim = _claim(dep)
    condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1
    claim.refresh_from_db()
    apply_claim_transition(claim, Status.SUPPORTED, actor=_user(), note="looks fine to me")
    RetestRequirement.objects.filter(deployment=dep).update(resolved_at=timezone.now())

    result = latent.evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert result["still_fired_count"] == 1 and result["fired_count"] == 0
    claim.refresh_from_db()
    condition.refresh_from_db()
    assert claim.status == Status.STALE
    reopened = RetestRequirement.objects.get(deployment=dep, resolved_at__isnull=True)
    assert condition.fired_requirement_id == reopened.pk
    assert "still holds" in ClaimEvent.objects.filter(claim=claim).order_by("-pk").first().note


# ---------------------------------------------------------------------------
# A condition nobody can read is read again, and holds the decision back meanwhile
# ---------------------------------------------------------------------------


def _vendor_watched(dep):
    vendor = Provider.objects.create(name="VendorX", kind=Provider.Kind.MODEL_PROVIDER)
    retention = ProviderAssertion.objects.create(
        provider=vendor, field="data_retention", value="0d", evidence_class=EvidenceClass.VENDOR_ASSERTED
    )
    condition = _declare(_claim(dep), kind=Kind.PROVIDER_POSTURE_CHANGES, subject="VendorX", expected="data_retention")
    return vendor, retention, condition


def _evaluate(dep):
    return latent.evaluate_conditions(Deployment.objects.get(pk=dep.pk))


def test_an_unobservable_condition_is_read_again_and_watches_again_once_its_subject_is_back():
    """A provider renamed and renamed back left the watch UNOBSERVABLE for good: the
    retention change it was declared for went by, and the deployment read READY."""
    dep = _ready()
    vendor, retention, condition = _vendor_watched(dep)

    Provider.objects.filter(pk=vendor.pk).update(name="VendorX Inc")
    assert _evaluate(dep)["unobservable_count"] == 1
    assert recompute_decision(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE

    Provider.objects.filter(pk=vendor.pk).update(name="VendorX")
    assert _evaluate(dep)["still_pending_count"] == 1
    condition.refresh_from_db()
    assert (condition.state, condition.fired_observation) == (State.PENDING, "")
    assert recompute_decision(dep) == Deployment.Decision.READY

    ProviderAssertion.objects.filter(pk=retention.pk).update(value="365d")
    assert _evaluate(dep)["fired_count"] == 1


def test_an_unobservable_condition_whose_subject_comes_back_changed_fires():
    dep = _ready()
    vendor, retention, condition = _vendor_watched(dep)
    Provider.objects.filter(pk=vendor.pk).update(name="VendorX Inc")
    _evaluate(dep)
    ProviderAssertion.objects.filter(pk=retention.pk).update(value="365d")
    Provider.objects.filter(pk=vendor.pk).update(name="VendorX")

    assert _evaluate(dep)["fired_count"] == 1

    condition.refresh_from_db()
    assert condition.state == State.FIRED
    assert condition.claim.status == Status.STALE
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).count() == 1


def test_a_condition_nobody_can_read_holds_the_decision_back_and_the_note_names_its_claim():
    dep = _ready()
    claim, condition = _training_watched(dep)
    DataBoundary.objects.filter(deployment=dep).delete()
    _evaluate(dep)
    condition.refresh_from_db()
    assert condition.state == State.UNOBSERVABLE

    signal = claim_decision_signal(dep)
    assert signal["cap"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [c.pk for c in signal["unread_conditions"]] == [condition.pk]
    assert recompute_decision(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    support = decision_support(dep)
    assert "cannot be checked" in support["note"] and "data_boundary" in support["note"]
    assert [c["uuid"] for c in support["claims"]["unread_conditions"]] == [str(condition.uuid)]
    # Not on a claim a person took out of scope: it is no mark against readiness.
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=Status.REVOKED)
    assert claim_decision_signal(dep)["cap"] is None


def test_the_same_watch_is_a_409_while_it_is_live_and_can_be_declared_again_once_withdrawn():
    """The declaration was unique on every row, a withdrawn one included, so the same
    watch could never be declared again on that claim, and the route answered 500."""
    dep = _ready()
    claim = _claim(dep)
    client = _client()
    url = f"/api/assurance/claims/{claim.uuid}/latent-conditions/"
    body = {"kind": Kind.ASSET_APPEARS, "subject": "shadow-exporter", "description": "first wording"}

    first = client.post(url, body, format="json")
    assert first.status_code == 201, first.content
    again = client.post(url, {**body, "description": "second wording"}, format="json")
    assert again.status_code == 409, again.content
    assert "already has this condition declared" in again.json()["detail"]
    assert again.json()["existing"]["uuid"] == first.json()["uuid"]
    LatentCondition.objects.filter(uuid=first.json()["uuid"]).update(state=State.FIRED)
    assert client.post(url, body, format="json").status_code == 409

    withdrawn = client.post(f"{url}{first.json()['uuid']}/withdraw/", {"note": "reword it"}, format="json")
    assert withdrawn.status_code == 200, withdrawn.content
    redeclared = client.post(url, {**body, "description": "second wording"}, format="json")
    assert redeclared.status_code == 201, redeclared.content
    assert LatentCondition.objects.filter(claim=claim, subject="shadow-exporter").count() == 2


def test_the_declaration_is_unique_among_live_conditions_only():
    """The constraint spells its states out (Meta cannot read the model's own), so
    they are held to the ones every evaluation reads."""
    constraint = next(c for c in LatentCondition._meta.constraints if c.name == "uq_latent_condition_declaration")
    ((lookup, states),) = constraint.condition.children
    assert lookup == "state__in"
    assert set(states) == {str(s) for s in LATENT_LIVE_STATES}
    assert State.WITHDRAWN not in states


# ---------------------------------------------------------------------------
# One condition that cannot be evaluated does not take the others with it
# ---------------------------------------------------------------------------


def test_one_condition_whose_observer_raises_does_not_roll_back_the_others(monkeypatch):
    dep = _ready()
    boundary_claim, fires = _training_watched(dep)
    breaks = _declare(_claim(dep, AssuranceClaim.ClaimType.AI_BOM), kind=Kind.ASSET_APPEARS, subject="exporter")
    real = latent._OBSERVERS[Kind.ASSET_APPEARS]

    def raising(condition, deployment):
        raise RuntimeError("statement timeout; dsn=postgres://svc:hunter2@db/assurance")

    monkeypatch.setitem(latent._OBSERVERS, Kind.ASSET_APPEARS, raising)
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)

    result = _evaluate(dep)

    assert (result["fired_count"], result["evaluation_failed_count"]) == (1, 1)
    fires.refresh_from_db()
    boundary_claim.refresh_from_db()
    breaks.refresh_from_db()
    assert fires.state == State.FIRED and boundary_claim.status == Status.STALE
    assert breaks.state == State.EVALUATION_FAILED and breaks.last_error_at is not None
    assert "RuntimeError" in breaks.last_error
    assert "hunter2" not in breaks.last_error + breaks.fired_observation
    posture = latent_posture(dep)
    assert (posture["evaluation_failed"], posture["watching"]) == (1, 0)
    assert breaks.pk in [c.pk for c in claim_decision_signal(dep)["unread_conditions"]]

    monkeypatch.setitem(latent._OBSERVERS, Kind.ASSET_APPEARS, real)
    _evaluate(dep)
    breaks.refresh_from_db()
    assert (breaks.state, breaks.last_error_at, breaks.last_error) == (State.PENDING, None, "")


def test_a_fired_condition_whose_evaluation_fails_keeps_holding_its_claim(monkeypatch):
    dep = _ready()
    claim = _claim(dep)
    condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    assert _evaluate(dep)["fired_count"] == 1

    def raising(condition, deployment):
        raise RuntimeError("the observer broke")

    monkeypatch.setitem(latent._OBSERVERS, Kind.ASSET_APPEARS, raising)
    assert _evaluate(dep)["evaluation_failed_count"] == 1

    condition.refresh_from_db()
    claim.refresh_from_db()
    assert condition.state == State.FIRED and condition.last_error_at is not None
    assert claim.status == Status.STALE
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).exists()


def test_an_evaluation_that_cannot_run_at_all_leaves_no_condition_counted_as_watching(monkeypatch, caplog):
    dep = _ready()
    condition = _declare(_claim(dep), kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    def broken(*args, **kwargs):
        raise RuntimeError("could not read; token=hunter2")

    monkeypatch.setattr(latent, "evaluate_conditions", broken)

    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 0

    condition.refresh_from_db()
    assert condition.state == State.EVALUATION_FAILED
    assert "RuntimeError" in condition.last_error and "hunter2" not in condition.last_error
    assert "were not evaluated" in caplog.text
    assert latent_posture(dep)["watching"] == 0
    assert recompute_decision(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


# ---------------------------------------------------------------------------
# 0037 and 0038 carry what a re-derive left behind without colliding
# ---------------------------------------------------------------------------


def _next_version(dep, old):
    """A re-derive as it went before: a new version, and nothing carried to it."""
    AssuranceClaim.objects.filter(pk=old.pk).update(valid_to=timezone.now(), status=Status.SUPERSEDED)
    new = AssuranceClaim.objects.create(
        deployment=dep, claim_type=old.claim_type, statement=old.statement, fingerprint=old.fingerprint,
        system_fingerprint="moved", policy_version=old.policy_version, environment=dep.environment,
        status=Status.SUPPORTED,
    )
    AssuranceClaim.objects.filter(pk=old.pk).update(superseded_by=new)
    return new


def _migration(name):
    from importlib import import_module

    return import_module(f"assurance.migrations.{name}")


def test_0037_merges_a_left_behind_watch_the_current_version_already_carries():
    """Re-declared on the new version by an operator who saw it left behind, or a
    second orphan of it on the same chain: the move raised IntegrityError and the
    whole migration aborted."""
    from django.apps import apps

    carry_forward = _migration("0037_carry_watches_and_legal_rulings").carry_forward
    dep = _ready()
    v1 = _claim(dep)
    left = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    v2 = _next_version(dep, v1)
    redeclared = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    for _ in range(2):  # the second pass changes nothing
        carry_forward(apps, None)
        left.refresh_from_db()
        redeclared.refresh_from_db()
        assert (left.claim_id, left.state) == (v1.pk, State.WITHDRAWN)
        assert left.fired_observation.startswith("Merged into the same declaration") and str(redeclared.uuid) in left.fired_observation
        assert (redeclared.claim_id, redeclared.state) == (v2.pk, State.PENDING)


def test_0037_carries_the_newest_of_two_orphans_on_one_chain_and_merges_the_other():
    from django.apps import apps

    dep = _ready()
    v1 = _claim(dep)
    older = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    v2 = _next_version(dep, v1)
    newer = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    v3 = _next_version(dep, v2)

    _migration("0037_carry_watches_and_legal_rulings").carry_forward(apps, None)

    older.refresh_from_db()
    newer.refresh_from_db()
    assert (newer.claim_id, newer.state) == (v3.pk, State.PENDING)
    assert older.state == State.WITHDRAWN and "Merged" in older.fired_observation


def test_0038_carries_a_fired_condition_left_behind_and_merges_one_already_re_declared():
    from django.apps import apps

    carry = _migration("0038_latent_conditions_stay_watched").carry_fired_forward
    dep = _ready()
    boundary_v1 = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    bom_v1 = _claim(dep, AssuranceClaim.ClaimType.AI_BOM)
    carried = _declare(boundary_v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    merged = _declare(bom_v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    LatentCondition.objects.filter(pk__in=[carried.pk, merged.pk]).update(state=State.FIRED)
    boundary_v2 = _next_version(dep, boundary_v1)
    bom_v2 = _next_version(dep, bom_v1)
    redeclared = _declare(bom_v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    carry(apps, None)

    carried.refresh_from_db()
    merged.refresh_from_db()
    redeclared.refresh_from_db()
    assert (carried.claim_id, carried.state) == (boundary_v2.pk, State.FIRED)
    assert (merged.claim_id, merged.state) == (bom_v1.pk, State.WITHDRAWN)
    assert str(redeclared.uuid) in merged.withdrawn_note and merged.withdrawn_at is not None
    assert (redeclared.claim_id, redeclared.state) == (bom_v2.pk, State.PENDING)


# ---------------------------------------------------------------------------
# A provider write brings the deployments that watch it current after it commits
# ---------------------------------------------------------------------------


def test_a_provider_write_evaluates_no_watching_deployment_inside_its_own_transaction(
    monkeypatch, django_capture_on_commit_callbacks
):
    """A PATCH to an assertion evaluated and refreshed, under its row lock, every
    deployment watching the provider -- all inside the PATCH's own transaction."""
    with django_capture_on_commit_callbacks(execute=True):  # the set-up commits
        vendor = Provider.objects.create(name="SharedVendor", kind=Provider.Kind.MODEL_PROVIDER)
        retention = ProviderAssertion.objects.create(
            provider=vendor, field="data_retention", value="0d", evidence_class=EvidenceClass.VENDOR_ASSERTED
        )
        deployments = [_ready() for _ in range(3)]
        conditions = [
            _declare(_claim(d), kind=Kind.PROVIDER_POSTURE_CHANGES, subject="SharedVendor", expected="data_retention")
            for d in deployments
        ]
    evaluated = []
    real = latent.evaluate_conditions

    def counting(deployment, **kwargs):
        evaluated.append(deployment.pk)
        return real(deployment, **kwargs)

    monkeypatch.setattr(latent, "evaluate_conditions", counting)

    with django_capture_on_commit_callbacks(execute=True) as hooks:
        written = _client().patch(f"/api/assurance/provider-assertions/{retention.uuid}/", {"value": "365d"}, format="json")
        assert written.status_code == 200, written.content
        assert evaluated == [], "a watching deployment was evaluated inside the write"

    ids = {d.pk for d in deployments}
    assert {h.deployment_id for h in hooks if isinstance(h, signals._RefreshAfterCommit)} >= ids
    assert set(evaluated) == ids
    for dep, condition in zip(deployments, conditions):
        condition.refresh_from_db()
        dep.refresh_from_db()
        assert condition.state == State.FIRED
        assert dep.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE


# ---------------------------------------------------------------------------
# Two conditions that fire on one claim mark it stale once
# ---------------------------------------------------------------------------


def test_two_conditions_that_fire_on_one_claim_mark_it_stale_once():
    dep = _ready()
    claim = _claim(dep)
    for name in ("exporter-a", "exporter-b"):
        _declare(claim, kind=Kind.ASSET_APPEARS, subject=name)
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name=name, identifier=name, classification=Asset.Classification.KNOWN
        )

    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 2

    moves = ClaimEvent.objects.filter(claim=claim, to_status=Status.STALE).exclude(from_status=Status.STALE)
    assert moves.count() == 1
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).count() == 1
