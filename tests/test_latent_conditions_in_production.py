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

import contextlib

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


@contextlib.contextmanager
def _committed():
    """What production does when a write's transaction commits: the hooks it scheduled
    run, before the response is sent -- the backstop, which evaluates the declared
    conditions after the commit and never inside the write (tests/
    test_nothing_that_watches_holds_back_a_stop.py). Each test runs in a transaction
    that is rolled back, so without this nothing a write scheduled would run.

    The writes before this one committed too, each on its own: what they scheduled
    runs first. Left pending, a refresh one of them scheduled stood in for the one
    this write schedules -- one per deployment per transaction -- and never ran."""
    from django.db import connection
    from django.test import TestCase

    earlier = list(connection.run_on_commit)
    del connection.run_on_commit[:]
    for _savepoints, callback, _robust in earlier:
        callback()
    with TestCase.captureOnCommitCallbacks(execute=True):
        yield


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

    with _committed():
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


def test_a_boundary_write_that_makes_a_declared_condition_true_fires_it_once_that_write_commits():
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

    with _committed():
        written = client.patch(
            f"/api/assurance/deployments/{dep.uuid}/data-boundary/", {"training_allowed": True}, format="json"
        )

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
    """It is evaluated once the write it follows has committed -- a person contradicting
    a claim among them -- never inside it. A failure there is logged, the write stands,
    and the condition is recorded as not evaluated. (A revoke, the write this used, now
    schedules no evaluation at all; see the revoke test below.)"""
    with django_capture_on_commit_callbacks(execute=True):  # the set-up commits
        dep = _ready()
        claim = _claim(dep)
        condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    def broken(*args, **kwargs):
        raise RuntimeError("the observer broke")

    monkeypatch.setattr(latent, "evaluate_conditions", broken)
    with django_capture_on_commit_callbacks(execute=True):
        moved = _client().post(
            f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "contradicted"}, format="json"
        )

    assert moved.status_code == 200, moved.content
    claim.refresh_from_db()
    condition.refresh_from_db()
    assert claim.status == Status.CONTRADICTED
    # On a claim still current and unrevoked the failure is recorded on the condition
    # -- read as unread by the decision -- where on the revoked claim it was left alone.
    assert condition.state == State.EVALUATION_FAILED
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


def test_the_carry_migrations_bring_a_left_behind_watch_and_ruling_to_the_current_version():
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
        _run_data_steps("0037_carry_watches_and_legal_rulings")
        _run_data_steps("0038_latent_conditions_stay_watched")
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


def test_a_revoke_evaluates_no_condition_before_or_after_it_commits(
    monkeypatch, django_capture_on_commit_callbacks
):
    """A revoke is a stop, and nothing that watches may delay one. It evaluated every
    condition on the deployment inline, before it could commit -- 2.3 seconds with a
    hundred principal conditions over three hundred tools. Then it read them once it
    had committed -- still before its response, which waited 0.7 s on 5,000 watches.
    Now the revoke recomputes the decision in its own transaction and answers; it
    changes nothing a watch reads, so nothing evaluates them for it."""
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

    assert not any(isinstance(h, signals._RefreshAfterCommit) and h.deployment_id == dep.pk for h in hooks)
    for hook in hooks:  # the revoke commits
        hook()
    assert observed == [], "a condition was evaluated after the revoke, before its response"
    assert len(conditions) == LatentCondition.objects.filter(deployment=dep, state=State.PENDING).count()


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
    with _committed():
        response = client.patch(
            f"/api/assurance/deployments/{dep.uuid}/data-boundary/", {"training_allowed": allowed}, format="json"
        )
    assert response.status_code == 200, response.content


def _re_derive(client, dep):
    with _committed():
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


def test_0038_merges_a_left_behind_watch_the_current_version_already_carries():
    """Re-declared on the new version by an operator who saw it left behind, or a
    second orphan of it on the same chain: the move raised IntegrityError and the
    whole migration aborted. The newest statement stands; the other is withdrawn."""
    dep = _ready()
    v1 = _claim(dep)
    left = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    v2 = _next_version(dep, v1)
    redeclared = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    for _ in range(2):  # the second pass changes nothing
        _run_data_steps("0038_latent_conditions_stay_watched")
        left.refresh_from_db()
        redeclared.refresh_from_db()
        assert (left.claim_id, left.state) == (v1.pk, State.WITHDRAWN)
        assert left.withdrawn_note.startswith("Merged into the same declaration")
        assert str(redeclared.uuid) in left.withdrawn_note and left.withdrawn_at is not None
        assert (redeclared.claim_id, redeclared.state) == (v2.pk, State.PENDING)


def test_0038_carries_the_newest_of_two_orphans_on_one_chain_and_merges_the_other():
    dep = _ready()
    v1 = _claim(dep)
    older = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    v2 = _next_version(dep, v1)
    newer = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    v3 = _next_version(dep, v2)

    _run_data_steps("0038_latent_conditions_stay_watched")

    older.refresh_from_db()
    newer.refresh_from_db()
    assert (newer.claim_id, newer.state) == (v3.pk, State.PENDING)
    assert older.state == State.WITHDRAWN and "Merged" in older.withdrawn_note


def test_0038_carries_a_fired_condition_left_behind_over_one_re_declared_since():
    """A fired statement is never the one withdrawn: withdrawing it accepts the state
    it fired on, which only a person may do. The re-declaration is withdrawn instead."""
    dep = _ready()
    boundary_v1 = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    bom_v1 = _claim(dep, AssuranceClaim.ClaimType.AI_BOM)
    carried = _declare(boundary_v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    fired = _declare(bom_v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    LatentCondition.objects.filter(pk__in=[carried.pk, fired.pk]).update(state=State.FIRED)
    boundary_v2 = _next_version(dep, boundary_v1)
    bom_v2 = _next_version(dep, bom_v1)
    redeclared = _declare(bom_v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    _run_data_steps("0038_latent_conditions_stay_watched")

    carried.refresh_from_db()
    fired.refresh_from_db()
    redeclared.refresh_from_db()
    assert (carried.claim_id, carried.state) == (boundary_v2.pk, State.FIRED)
    assert (fired.claim_id, fired.state, fired.withdrawn_at) == (bom_v2.pk, State.FIRED, None)
    assert (redeclared.claim_id, redeclared.state) == (bom_v2.pk, State.WITHDRAWN)
    assert str(fired.uuid) in redeclared.withdrawn_note and redeclared.withdrawn_at is not None


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


def test_the_unread_condition_cap_is_named_in_the_policy_document():
    """Named there, so the policy pin moves with it and every decision stored under
    the pin before is recomputed under it (Deployment.decision_policy), rather than
    published READY over a precondition nobody can read."""
    from assurance.policy import POLICY

    caps = POLICY["decision"]["claim_caps"]
    assert caps["unread_latent_condition"] == Deployment.Decision.NEEDS_MORE_EVIDENCE


def _chain_left_by_the_old_re_derive(statuses):
    """A claim's versions as the re-derive left them before it carried the legal
    axis: each opened "not assessed", then marked with what happened on it. The
    last is current."""
    dep = _ready()
    first = _claim(dep)
    versions = [first]
    for _ in statuses[1:]:
        prior = versions[-1]
        # Closed before its successor opens, as the re-derive does: one open version
        # per claim.
        AssuranceClaim.objects.filter(pk=prior.pk).update(
            valid_to=timezone.now(), status=Status.SUPERSEDED
        )
        successor = AssuranceClaim.objects.create(
            deployment=dep, claim_type=prior.claim_type, statement=prior.statement,
            fingerprint=prior.fingerprint, system_fingerprint=f"moved-{len(versions)}",
            policy_version=prior.policy_version, environment=dep.environment,
            status=Status.SUPPORTED,
        )
        AssuranceClaim.objects.filter(pk=prior.pk).update(superseded_by=successor)
        versions.append(successor)
    for version, status in zip(versions, statuses):
        AssuranceClaim.objects.filter(pk=version.pk).update(legal_status=status)
    return versions[-1]


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ((LegalStatus.STALE, LegalStatus.REVIEW_PENDING), LegalStatus.STALE),
        ((LegalStatus.STALE, LegalStatus.NOT_ASSESSED, LegalStatus.REVIEW_PENDING), LegalStatus.STALE),
        ((LegalStatus.STALE, LegalStatus.NOT_ASSESSED), LegalStatus.STALE),
        ((LegalStatus.CURRENT, LegalStatus.REVIEW_PENDING), LegalStatus.REVIEW_PENDING),
        ((LegalStatus.CURRENT, LegalStatus.NOT_ASSESSED), LegalStatus.CURRENT),
        ((LegalStatus.STALE, LegalStatus.CURRENT), LegalStatus.CURRENT),
        ((LegalStatus.REVIEW_PENDING, LegalStatus.NOT_ASSESSED), LegalStatus.REVIEW_PENDING),
    ],
    ids=[
        "a flag after a lost stale ruling",
        "a flag two versions after it",
        "a lost stale ruling",
        "a flag after a current ruling",
        "a lost current ruling",
        "a person's later ruling stands",
        "a lost pending review",
    ],
)
def test_0037_replays_the_legal_axis_as_the_carry_would_have_left_it(statuses, expected):
    """Restoring only onto a version still "not assessed" missed a stale ruling whose
    version a review was later flagged on: the flag left it "pending" and the
    person's STALE -- which a flag leaves alone -- stayed lost, capping nothing."""
    current = _chain_left_by_the_old_re_derive(statuses)
    for _ in range(2):  # the second pass changes nothing
        _run_data_steps("0037_carry_watches_and_legal_rulings")
        current.refresh_from_db()
        assert current.legal_status == expected


# ---------------------------------------------------------------------------
# Round 2 of #105: a fired condition holds its claim wherever it is read from
# ---------------------------------------------------------------------------


def _run_data_steps(name):
    """Every data step of migration ``name``, as `migrate` runs it."""
    from django.apps import apps
    from django.db.migrations.operations import RunPython

    for operation in _migration(name).Migration.operations:
        if isinstance(operation, RunPython):
            operation.code(apps, None)


def _upgrade(django_capture_on_commit_callbacks):
    """What `migrate` does on the upgrade from main: the carry migrations' data steps,
    then every post_migrate receiver, each hook they schedule run as its commit runs it."""
    from django.core.management.sql import emit_post_migrate_signal

    _run_data_steps("0037_carry_watches_and_legal_rulings")
    _run_data_steps("0038_latent_conditions_stay_watched")
    with django_capture_on_commit_callbacks(execute=True):
        emit_post_migrate_signal(verbosity=0, interactive=False, db="default")


def _open_retests(dep, claim):
    return RetestRequirement.objects.filter(
        deployment=dep, claim__fingerprint=claim.fingerprint, resolved_at__isnull=True
    )


def _as_main_left_it(dep, claim):
    """What main's routine re-derive left after a condition fired on ``claim``: a new
    version reading its deriver's pass, the retest resolved, the condition on the
    version it closed -- and the decision stored READY with no policy stamp, a column
    main does not have."""
    new = _next_version(dep, claim)
    AssuranceClaim.objects.filter(pk=new.pk).update(status=Status.VERIFIED)
    RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).update(
        resolved_at=timezone.now(), resolving_claim=new
    )
    Deployment.objects.filter(pk=dep.pk).update(decision=Deployment.Decision.READY, decision_policy=None)
    return AssuranceClaim.objects.get(pk=new.pk)


def test_after_the_upgrade_a_claim_a_fired_condition_holds_is_not_published_ready(
    django_capture_on_commit_callbacks,
):
    """Main fired the watch, and a routine re-derive read the claim back to VERIFIED
    and resolved its retest. After `migrate` the condition sat FIRED on the current
    version while the stored decision, current_decision() and decision_support() all
    read READY, with no retest open -- and nothing but a later write would fix it."""
    from assurance.decision import current_decision
    from assurance.revalidation import plan_revalidation

    dep = _derived_ready()
    claim, condition = _training_watched(dep)
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1
    current = _as_main_left_it(dep, claim)

    _upgrade(django_capture_on_commit_callbacks)

    fresh = Deployment.objects.get(pk=dep.pk)
    assert fresh.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE, "the stored decision"
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert decision_support(Deployment.objects.get(pk=dep.pk))["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    condition.refresh_from_db()
    current.refresh_from_db()
    assert (condition.state, condition.claim_id) == (State.FIRED, current.pk)
    assert current.status == Status.STALE
    assert _open_retests(dep, current).exists()
    assert str(current.uuid) in [w["claim_uuid"] for w in plan_revalidation(dep)["required"]]


def test_a_claim_a_fired_condition_holds_caps_the_decision_whatever_its_row_reads():
    """The hold is on the claim, and the decision reads it there: not only through
    the STALE mark and the retest, which anything that writes a claim row can undo."""
    from assurance.revalidation import plan_revalidation

    dep = _derived_ready()
    claim, condition = _training_watched(dep)
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=Status.VERIFIED)
    RetestRequirement.objects.filter(deployment=dep).update(resolved_at=timezone.now())

    signal = claim_decision_signal(dep)
    assert signal["cap"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [c.pk for c in signal["held"]] == [claim.pk]
    assert claim.pk not in [c.pk for c in signal["supporting"]]
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    support = decision_support(Deployment.objects.get(pk=dep.pk))
    assert support["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [c["uuid"] for c in support["claims"]["held"]] == [str(claim.uuid)]
    assert "fired" in support["note"] and "data_boundary" in support["note"]
    required = {w["claim_uuid"]: w for w in plan_revalidation(dep)["required"]}
    assert str(claim.uuid) in required
    assert "safe only while training stays denied" in required[str(claim.uuid)]["reason"]


def test_a_fired_condition_that_loses_sight_of_its_subject_keeps_and_restores_its_hold():
    """Out of sight is not back at its baseline. The hold stands -- and where
    something removed it, it is put back, as it is for a condition still read true."""
    dep = _derived_ready()
    vendor, retention, condition = _vendor_watched(dep)
    claim = condition.claim
    ProviderAssertion.objects.filter(pk=retention.pk).update(value="365d")
    assert _evaluate(dep)["fired_count"] == 1
    Provider.objects.filter(pk=vendor.pk).update(name="VendorX Inc")
    claim.refresh_from_db()
    apply_claim_transition(claim, Status.SUPPORTED, actor=_user(), note="looks fine to me")
    RetestRequirement.objects.filter(deployment=dep).update(resolved_at=timezone.now())

    result = _evaluate(dep)

    assert (result["still_fired_count"], result["unobservable_count"]) == (1, 0)
    condition.refresh_from_db()
    claim.refresh_from_db()
    assert condition.state == State.FIRED
    assert claim.status == Status.STALE
    assert _open_retests(dep, claim).exists()
    # And a re-derive reads it no better, the subject still out of sight.
    derive_claims(Deployment.objects.get(pk=dep.pk))
    current = AssuranceClaim.objects.get(deployment=dep, fingerprint=claim.fingerprint, valid_to__isnull=True)
    condition.refresh_from_db()
    assert (condition.state, condition.claim_id) == (State.FIRED, current.pk)
    assert current.status == Status.STALE
    assert _open_retests(dep, current).exists()
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_an_evaluation_that_cannot_run_at_all_keeps_a_fired_condition_fired(monkeypatch, caplog):
    dep = _ready()
    claim = _claim(dep)
    condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1
    real = latent.evaluate_conditions

    def broken(*args, **kwargs):
        raise RuntimeError("could not read")

    monkeypatch.setattr(latent, "evaluate_conditions", broken)
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 0

    condition.refresh_from_db()
    assert condition.state == State.FIRED
    assert condition.last_error_at is not None and "RuntimeError" in condition.last_error
    assert "were not evaluated" in caplog.text
    monkeypatch.setattr(latent, "evaluate_conditions", real)
    derive_claims(Deployment.objects.get(pk=dep.pk))
    current = AssuranceClaim.objects.get(deployment=dep, fingerprint=claim.fingerprint, valid_to__isnull=True)
    assert current.status == Status.STALE
    assert _open_retests(dep, current).exists()
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE


@pytest.mark.parametrize(
    ("state", "refreshed"),
    [
        (State.UNOBSERVABLE, True),
        (State.EVALUATION_FAILED, True),
        (State.FIRED, True),
        (State.PENDING, False),
    ],
    ids=["unobservable", "evaluation-failed", "fired", "pending"],
)
def test_a_condition_written_whole_in_a_state_the_decision_reads_schedules_a_refresh(
    django_capture_on_commit_callbacks, state, refreshed
):
    """An admin or a shell can write the row whole, in any state. One the decision
    reads -- unread, or FIRED, which holds its claim -- must refresh it."""
    with django_capture_on_commit_callbacks(execute=True):  # the set-up commits
        dep = _ready()
        claim = _claim(dep)
    with django_capture_on_commit_callbacks() as hooks:
        LatentCondition.objects.create(
            deployment=dep, claim=claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter",
            description="written whole", state=state,
        )
    scheduled = [h.deployment_id for h in hooks if isinstance(h, signals._RefreshAfterCommit)]
    assert (dep.pk in scheduled) is refreshed


def test_a_boundary_write_the_admin_or_a_shell_makes_fires_a_boundary_watch_when_it_commits(
    django_capture_on_commit_callbacks,
):
    with django_capture_on_commit_callbacks(execute=True):  # the set-up commits
        dep = _ready()
        claim, condition = _training_watched(dep)

    with django_capture_on_commit_callbacks(execute=True) as hooks:
        boundary = DataBoundary.objects.get(deployment=dep)
        boundary.training_allowed = True
        boundary.save()

    assert any(isinstance(h, signals._RefreshAfterCommit) and h.deployment_id == dep.pk for h in hooks)
    condition.refresh_from_db()
    claim.refresh_from_db()
    dep.refresh_from_db()
    assert condition.state == State.FIRED
    assert claim.status == Status.STALE
    assert dep.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_the_upgrade_keeps_the_newest_statement_of_a_watch_and_never_withdraws_one_that_fired(
    django_capture_on_commit_callbacks,
):
    """Main left an operator to re-declare a watch its re-derive dropped. The older
    statement stayed PENDING on v1; the newer one, on v2, fired. 0037 carried the
    older to the current version first, and 0038 then withdrew the newer, FIRED
    statement as a duplicate of it: the precondition stayed broken and the
    deployment read READY."""
    from assurance.decision import current_decision

    dep = _derived_ready()
    vendor = Provider.objects.create(name="VendorX", kind=Provider.Kind.MODEL_PROVIDER)
    retention = ProviderAssertion.objects.create(
        provider=vendor, field="data_retention", value="0d", evidence_class=EvidenceClass.VENDOR_ASSERTED
    )
    watch = dict(kind=Kind.PROVIDER_POSTURE_CHANGES, subject="VendorX", expected="data_retention")
    v1 = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    older = _declare(v1, description="first statement of the watch", **watch)
    v2 = _next_version(dep, v1)
    ProviderAssertion.objects.filter(pk=retention.pk).update(value="30d")
    newer = _declare(v2, description="re-declared: safe only while retention stays 30d", **watch)
    ProviderAssertion.objects.filter(pk=retention.pk).update(value="0d")
    assert _evaluate(dep)["fired_count"] == 1
    v3 = _as_main_left_it(dep, v2)

    _upgrade(django_capture_on_commit_callbacks)

    older.refresh_from_db()
    newer.refresh_from_db()
    assert (newer.state, newer.claim_id, newer.withdrawn_at) == (State.FIRED, v3.pk, None)
    assert (older.state, older.claim_id) == (State.WITHDRAWN, v1.pk)
    assert str(newer.uuid) in older.withdrawn_note
    v3.refresh_from_db()
    assert v3.status == Status.STALE
    assert _open_retests(dep, v3).exists()
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_the_upgrade_withdraws_no_fired_statement_where_two_statements_of_a_watch_fired():
    from assurance.claims import held_by_fired_conditions

    dep = _ready()
    v1 = _claim(dep)
    first = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    v2 = _next_version(dep, v1)
    second = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    LatentCondition.objects.filter(pk__in=[first.pk, second.pk]).update(state=State.FIRED)
    v3 = _next_version(dep, v2)

    for _ in range(2):  # the second pass changes nothing
        _run_data_steps("0037_carry_watches_and_legal_rulings")
        _run_data_steps("0038_latent_conditions_stay_watched")
        first.refresh_from_db()
        second.refresh_from_db()
        assert (second.claim_id, second.state) == (v3.pk, State.FIRED)
        # Left where it fired, still holding the claim -- a migration withdraws no
        # fired watch; a person withdrawing it is the only thing that accepts it.
        assert (first.claim_id, first.state, first.withdrawn_at) == (v1.pk, State.FIRED, None)
    assert v3.fingerprint in held_by_fired_conditions(dep)


def test_the_upgrade_keeps_a_fired_statement_over_a_later_pending_one_and_withdraws_that():
    dep = _ready()
    v1 = _claim(dep)
    fired = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    LatentCondition.objects.filter(pk=fired.pk).update(state=State.FIRED, fired_observation="it appeared")
    v2 = _next_version(dep, v1)
    pending = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")

    _run_data_steps("0037_carry_watches_and_legal_rulings")
    _run_data_steps("0038_latent_conditions_stay_watched")

    fired.refresh_from_db()
    pending.refresh_from_db()
    assert (fired.claim_id, fired.state, fired.fired_observation) == (v2.pk, State.FIRED, "it appeared")
    assert (pending.claim_id, pending.state) == (v2.pk, State.WITHDRAWN)
    assert str(fired.uuid) in pending.withdrawn_note and pending.withdrawn_at is not None


def test_the_upgrade_carries_a_fired_watch_past_a_withdrawn_re_declaration_and_leaves_that_alone():
    """A withdrawn row is a record, not a watch: nothing is merged into it, and
    nothing about it is rewritten."""
    dep = _ready()
    v1 = _claim(dep)
    fired = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    LatentCondition.objects.filter(pk=fired.pk).update(state=State.FIRED, fired_observation="it appeared")
    v2 = _next_version(dep, v1)
    redeclared = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    LatentCondition.objects.filter(pk=redeclared.pk).update(state=State.WITHDRAWN, fired_observation="not needed")
    fields = ["state", "claim_id", "fired_observation", "withdrawn_at", "withdrawn_note", "withdrawn_by_id"]
    before = LatentCondition.objects.filter(pk=redeclared.pk).values(*fields).get()

    _run_data_steps("0037_carry_watches_and_legal_rulings")
    _run_data_steps("0038_latent_conditions_stay_watched")

    fired.refresh_from_db()
    assert (fired.claim_id, fired.state, fired.withdrawn_at) == (v2.pk, State.FIRED, None)
    assert LatentCondition.objects.filter(pk=redeclared.pk).values(*fields).get() == before


def _obligations(dep):
    import datetime

    from assurance.models import LegalObligation

    made = []
    for source, operative in (("GDPR", datetime.date(2026, 1, 1)), ("AI Act", datetime.date(2026, 8, 1))):
        obligation = LegalObligation.objects.create(
            jurisdiction="EU", authority_tier=LegalObligation.AuthorityTier.REGULATION, source=source,
            source_version="1", operative_date=operative,
        )
        obligation.deployments.add(dep)
        made.append(obligation)
    return made


def test_0037_replays_a_persons_later_ruling_and_the_flag_after_it_in_the_order_they_happened():
    """v1 ruled material (STALE); main's re-derive opened v2 not assessed; the person
    ruled v2 NOT material (CURRENT); a later obligation flagged v2 for review. The
    replay from each version's last status read STALE, then a flag, and restored
    STALE over the person's own later ruling -- a legal judgment nobody made."""
    from assurance.legal import flag_for_materiality_review, record_materiality_decision

    dep = _ready()
    person = _user()
    gdpr, ai_act = _obligations(dep)
    v1 = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    record_materiality_decision(v1, gdpr, decided_by=person, material=True, rationale="the Art. 28 change is material")
    v2 = _next_version(dep, v1)
    record_materiality_decision(v2, gdpr, decided_by=person, material=False, rationale="not material any more")
    flag_for_materiality_review(ai_act)
    v2.refresh_from_db()
    assert v2.legal_status == LegalStatus.REVIEW_PENDING
    events = ClaimEvent.objects.filter(claim=v2).count()

    for _ in range(2):  # the second pass changes nothing
        _run_data_steps("0037_carry_watches_and_legal_rulings")
        v2.refresh_from_db()
        assert v2.legal_status == LegalStatus.REVIEW_PENDING
        assert ClaimEvent.objects.filter(claim=v2).count() == events


def test_0037_records_every_legal_status_it_moves():
    from assurance.legal import record_materiality_decision

    dep = _ready()
    gdpr, _ai_act = _obligations(dep)
    v1 = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    record_materiality_decision(v1, gdpr, decided_by=_user(), material=True, rationale="material")
    v2 = _next_version(dep, v1)
    assert v2.legal_status == LegalStatus.NOT_ASSESSED

    for _ in range(2):  # the second pass changes nothing
        _run_data_steps("0037_carry_watches_and_legal_rulings")
        v2.refresh_from_db()
        assert v2.legal_status == LegalStatus.STALE
        moved = ClaimEvent.objects.filter(claim=v2, note__contains="0037")
        assert moved.count() == 1
        assert f"{LegalStatus.NOT_ASSESSED} -> {LegalStatus.STALE}" in moved.get().note


@pytest.mark.parametrize(
    "name", ["0037_carry_watches_and_legal_rulings", "0038_latent_conditions_stay_watched"]
)
def test_the_carry_migrations_say_they_cannot_be_reversed(name):
    """0038's reverse re-adds the unconditional constraint, which a watch withdrawn
    and declared again violates: the reverse failed part-way on an IntegrityError.
    Undoing a carry would recreate the defect it repairs, so neither claims a reverse."""
    from django.db.migrations.operations import RunPython

    steps = [op for op in _migration(name).Migration.operations if isinstance(op, RunPython)]
    assert steps and not any(step.reversible for step in steps)


def test_every_column_this_release_adds_without_null_has_a_database_default():
    """Mid-rollout, a writer of the release before inserts rows without the columns
    this one adds. A NOT NULL column the database does not default refuses its every
    insert: it could not record a finding, declare a watch or ingest an outcome."""
    from django.db.migrations.operations import AddField
    from django.db.models.fields import NOT_PROVIDED

    undefaulted = [
        f"{operation.model_name}.{operation.name}"
        for name in (
            "0036_accepted_risk_expires",
            "0037_carry_watches_and_legal_rulings",
            "0038_latent_conditions_stay_watched",
            "0039_bind_chain_outcomes_to_their_route",
        )
        for operation in _migration(name).Migration.operations
        if isinstance(operation, AddField)
        and not operation.field.null
        and operation.field.db_default is NOT_PROVIDED
    ]
    assert undefaulted == []


# ---------------------------------------------------------------------------
# Round 3 of #105: whatever the release before writes mid-rollout, this one converges
# ---------------------------------------------------------------------------
#
# A rolling deploy keeps the release before this one writing AFTER 0037 and 0038 ran
# (the database defaults 0036-0039 give their columns are for exactly that). Its
# re-derive opened the new version "not assessed" and left every watch on the version
# it closed, and read a claim a fired condition holds back to a pass. Nothing one-shot
# can repair a write made after it ran.


def _decided_by_the_release_before(dep, decision):
    """The release before this one recording ``decision`` through ITS writer: the
    decision and its revision move with a transition, and the policy stamp -- a column
    it does not know -- is left where it was."""
    from assurance.models import DecisionTransition

    row = Deployment.objects.get(pk=dep.pk)
    revision = row.decision_revision + 1
    Deployment.objects.filter(pk=dep.pk).update(decision=decision, decision_revision=revision)
    DecisionTransition.objects.create(
        deployment=row, revision=revision, from_decision=row.decision or "", to_decision=decision or ""
    )


def _re_derived_by_the_release_before(dep, claim):
    """The release before this one re-deriving mid-rollout, after the migrations ran:
    a new version reading its deriver's pass, opened "not assessed" on the legal axis,
    every watch left on the version it closed, every retest resolved -- and the READY
    it computed under its own rules, recorded through its writer."""
    new = _next_version(dep, claim)
    AssuranceClaim.objects.filter(pk=new.pk).update(status=Status.VERIFIED)
    RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).update(
        resolved_at=timezone.now(), resolving_claim=new
    )
    _decided_by_the_release_before(dep, Deployment.Decision.READY)
    return AssuranceClaim.objects.get(pk=new.pk)


def _ruled_stale_and_watched(dep):
    from assurance.legal import record_materiality_decision

    gdpr, _ai_act = _obligations(dep)
    claim, condition = _training_watched(dep)
    record_materiality_decision(claim, gdpr, decided_by=_user(), material=True, rationale="the Art. 28 change is material")
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    return claim, condition


def test_a_ruling_and_a_watch_the_release_before_drops_mid_rollout_are_carried_back_at_the_first_read():
    """The adversary's rolling deploy: the release before re-derived after the
    migrations and left the current version "not assessed" and the watch on the
    version it closed -- for good. The decision read READY; the watch never fired."""
    from assurance.decision import current_decision

    dep = _derived_ready()
    claim, condition = _ruled_stale_and_watched(dep)
    current = _re_derived_by_the_release_before(dep, claim)
    assert current.legal_status == LegalStatus.NOT_ASSESSED

    # Read before anything repairs the rows: the ruling as the carry leaves it caps.
    support = decision_support(Deployment.objects.get(pk=dep.pk))
    assert support["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [c["uuid"] for c in support["claims"]["legally_stale"]] == [str(current.uuid)]
    # The first publishing read does not publish the READY the release before stored,
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    # and it carried the ruling and the watch to the current version, and says so.
    current.refresh_from_db()
    condition.refresh_from_db()
    assert current.legal_status == LegalStatus.STALE
    assert ClaimEvent.objects.filter(claim=current, note__startswith="Legal axis carried forward to this version").count() == 1
    assert (condition.state, condition.claim_id) == (State.PENDING, current.pk)
    posture = latent_posture(dep)
    assert (posture["watching"], posture["unwatched"]) == (1, 0)
    # The change the watch was declared for now fires it, on the current version.
    _allow_training(_client(), dep)
    condition.refresh_from_db()
    assert (condition.state, condition.claim_id) == (State.FIRED, current.pk)
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    # And a second pass writes nothing more.
    events = ClaimEvent.objects.filter(claim=current).count()
    from assurance.carry import converge

    assert not any(converge(Deployment.objects.get(pk=dep.pk)).values())
    assert ClaimEvent.objects.filter(claim=current).count() == events


def test_a_hold_the_release_before_lifts_mid_rollout_is_never_published_weaker_than_decision_support():
    """current_decision() published READY while decision_support() said needs more
    evidence: the release before moved the decision without the stamp, and the stamp
    named only the rules. And the condition stayed FIRED on the closed version,
    never evaluated again."""
    from assurance.decision import current_decision, refresh_stored_decisions

    dep = _derived_ready()
    claim, condition = _training_watched(dep)
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    current = _re_derived_by_the_release_before(dep, claim)

    support = decision_support(Deployment.objects.get(pk=dep.pk))["decision"]
    assert support == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == support
    condition.refresh_from_db()
    current.refresh_from_db()
    assert (condition.state, condition.claim_id) == (State.FIRED, current.pk)
    assert current.status == Status.STALE
    assert _open_retests(dep, current).exists()
    # The refresh every write schedules evaluates it there, and keeps it so.
    refresh_stored_decisions([dep.pk])
    assert _evaluate(dep)["still_fired"] == [str(condition.uuid)]
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_the_refresh_every_write_schedules_carries_what_the_release_before_left():
    """Not only a publishing read: the backstop after any write of this release."""
    from assurance.decision import refresh_stored_decisions

    dep = _derived_ready()
    claim, condition = _ruled_stale_and_watched(dep)
    current = _re_derived_by_the_release_before(dep, claim)
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)

    refresh_stored_decisions([dep.pk])

    condition.refresh_from_db()
    current.refresh_from_db()
    assert (condition.state, condition.claim_id) == (State.FIRED, current.pk), "carried, then evaluated"
    assert current.legal_status == LegalStatus.STALE
    assert current.status == Status.STALE
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_migrate_after_the_rollout_carries_what_the_release_before_left(django_capture_on_commit_callbacks):
    from django.core.management.sql import emit_post_migrate_signal

    dep = _derived_ready()
    claim, condition = _ruled_stale_and_watched(dep)
    current = _re_derived_by_the_release_before(dep, claim)

    with django_capture_on_commit_callbacks(execute=True):
        emit_post_migrate_signal(verbosity=0, interactive=False, db="default")

    condition.refresh_from_db()
    current.refresh_from_db()
    assert (condition.state, condition.claim_id) == (State.PENDING, current.pk)
    assert current.legal_status == LegalStatus.STALE
    fresh = Deployment.objects.get(pk=dep.pk)
    assert fresh.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE
    from assurance.decision import stamped_in_force

    assert stamped_in_force(fresh)


def test_the_decision_and_the_plan_read_a_hold_left_on_a_closed_version_before_anything_carries_it():
    """The hold is on the claim, on any version of it. Read only on the current
    version, a condition the release before left FIRED on the version it closed held
    nothing: nothing in the tests read it there."""
    from assurance.revalidation import plan_revalidation

    dep = _derived_ready()
    claim, condition = _training_watched(dep)
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1
    current = _re_derived_by_the_release_before(dep, claim)
    assert LatentCondition.objects.get(pk=condition.pk).claim_id == claim.pk

    signal = claim_decision_signal(Deployment.objects.get(pk=dep.pk))
    assert [c.pk for c in signal["held"]] == [current.pk]
    assert signal["cap"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    support = decision_support(Deployment.objects.get(pk=dep.pk))
    assert support["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [c["uuid"] for c in support["claims"]["held"]] == [str(current.uuid)]
    required = {w["claim_uuid"]: w for w in plan_revalidation(dep)["required"]}
    assert str(current.uuid) in required
    assert "safe only while training stays denied" in required[str(current.uuid)]["reason"]
    # Reading it moved nothing.
    assert LatentCondition.objects.get(pk=condition.pk).claim_id == claim.pk


def test_a_condition_nobody_can_read_left_on_a_closed_version_still_holds_the_decision_back():
    dep = _derived_ready()
    vendor, _retention, condition = _vendor_watched(dep)
    Provider.objects.filter(pk=vendor.pk).update(name="VendorX Inc")
    assert _evaluate(dep)["unobservable_count"] == 1
    _re_derived_by_the_release_before(dep, condition.claim)

    signal = claim_decision_signal(Deployment.objects.get(pk=dep.pk))
    assert [c.pk for c in signal["unread_conditions"]] == [condition.pk]
    assert signal["cap"] == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_the_carry_keeps_one_statement_of_a_watch_the_release_before_left_beside_a_re_declaration():
    """0038's rule, wherever the release before's writes are next seen: the newest
    statement is kept on the current version and the other withdrawn with a note;
    a FIRED statement is never withdrawn, and one already on the current version that
    fired is the one kept."""
    from assurance.carry import converge

    dep = _derived_ready()
    claim, older = _training_watched(dep)
    current = _re_derived_by_the_release_before(dep, claim)
    newer = _declare(current, kind=Kind.BOUNDARY_ALLOWS, subject="training", description="re-declared")

    converge(Deployment.objects.get(pk=dep.pk))

    older.refresh_from_db()
    newer.refresh_from_db()
    assert (newer.state, newer.claim_id) == (State.PENDING, current.pk)
    assert (older.state, older.claim_id) == (State.WITHDRAWN, claim.pk)
    assert str(newer.uuid) in older.withdrawn_note


def test_the_carry_keeps_a_fired_statement_already_on_the_current_version_over_a_newer_one_left_behind():
    """The older statement, on the current version, fired; a newer one fired on the
    version the release before closed. Keeping the newest would move it onto the
    current version beside the other: two live statements of one watch, which the
    declaration constraint refuses."""
    from assurance.carry import converge

    dep = _ready()
    v1 = _claim(dep)
    v2 = _next_version(dep, v1)
    on_current = _declare(v2, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    left = LatentCondition.objects.create(
        deployment=dep, claim=v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter",
        description="declared on v1 later", state=State.FIRED,
    )
    LatentCondition.objects.filter(pk=on_current.pk).update(
        state=State.FIRED, declared_at=timezone.now() - timezone.timedelta(days=1)
    )

    for step in ("0038", "carry"):
        if step == "0038":
            _run_data_steps("0038_latent_conditions_stay_watched")
        else:
            converge(Deployment.objects.get(pk=dep.pk))
        on_current.refresh_from_db()
        left.refresh_from_db()
        assert (on_current.state, on_current.claim_id) == (State.FIRED, v2.pk), step
        assert (left.state, left.claim_id) == (State.FIRED, v1.pk), step


def test_0038_does_not_merge_two_watches_that_differ_in_what_they_expect():
    """One watch is a declaration of (kind, subject, EXPECTED): two regions watched for
    are two watches. Grouped without it, one was merged into the other and withdrawn."""
    dep = _ready()
    v1 = _claim(dep)
    us = _declare(v1, kind=Kind.BOUNDARY_REGION_ADDED, subject="boundary", expected="us-east-1")
    ap = _declare(v1, kind=Kind.BOUNDARY_REGION_ADDED, subject="boundary", expected="ap-south-1")
    v2 = _next_version(dep, v1)

    _run_data_steps("0038_latent_conditions_stay_watched")

    us.refresh_from_db()
    ap.refresh_from_db()
    assert {(us.state, us.claim_id), (ap.state, ap.claim_id)} == {(State.PENDING, v2.pk)}


# ---- the hold put back without an evaluation: only where it is lifted, only there


def _fired_and_lifted(dep):
    """A condition fired on ``dep``'s claim, and both halves of its hold lifted."""
    claim = _claim(dep)
    condition = _declare(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    assert fire_due_conditions(Deployment.objects.get(pk=dep.pk)) == 1
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=Status.VERIFIED)
    RetestRequirement.objects.filter(deployment=dep).update(resolved_at=timezone.now())
    return claim, condition


@pytest.mark.parametrize("lifted", ["status", "retest"])
def test_a_hold_lifted_by_either_half_is_put_back(lifted):
    """Lifted is EITHER half gone: the claim reads a pass, or no retest is open. A
    check that needed both -- or read only the status -- left a claim STALE with no
    retest, or VERIFIED with one, as it found it."""
    dep = _ready()
    claim, _condition = _fired_and_lifted(dep)
    if lifted == "status":  # the retest is open again; only the status reads a pass
        RetestRequirement.objects.filter(deployment=dep).update(resolved_at=None)
    else:  # the claim is STALE again; only the retest is gone
        AssuranceClaim.objects.filter(pk=claim.pk).update(status=Status.STALE)

    assert latent.restore_fired_holds(Deployment.objects.get(pk=dep.pk)) == 1

    claim.refresh_from_db()
    assert claim.status == Status.STALE
    assert _open_retests(dep, claim).count() == 1


def test_a_hold_is_not_put_back_on_a_claim_a_person_revoked():
    dep = _ready()
    claim, _condition = _fired_and_lifted(dep)
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=Status.REVOKED)

    assert latent.restore_fired_holds(Deployment.objects.get(pk=dep.pk)) == 0

    claim.refresh_from_db()
    assert claim.status == Status.REVOKED
    assert not _open_retests(dep, claim).exists()


def test_putting_back_one_deployments_holds_touches_no_other_deployments_claims():
    one, other = _ready(), _ready()
    _fired_and_lifted(one)
    other_claim, _other = _fired_and_lifted(other)

    latent.restore_fired_holds(Deployment.objects.get(pk=one.pk))

    other_claim.refresh_from_db()
    assert other_claim.status == Status.VERIFIED
    assert not _open_retests(other, other_claim).exists()


def test_a_retest_put_back_for_a_condition_on_an_older_version_is_not_linked_to_it():
    """Two statements of one watch fired; one stays on the version it fired on. The
    retest put back is for the current version, and the one left behind -- which no
    evaluation reads -- is not made its owner."""
    dep = _ready()
    v1 = _claim(dep)
    left = _declare(v1, kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    LatentCondition.objects.filter(pk=left.pk).update(state=State.FIRED)
    v2 = _next_version(dep, v1)

    assert latent.restore_fired_holds(Deployment.objects.get(pk=dep.pk)) == 1

    left.refresh_from_db()
    assert left.claim_id == v1.pk and left.fired_requirement_id is None
    assert _open_retests(dep, v2).count() == 1


def test_a_fired_condition_evaluated_again_and_again_opens_one_retest_and_records_no_failure():
    """The put-back opens a retest only when none is open. Opening one every time hit
    the one-open-retest index on every evaluation, which recorded each as failed."""
    dep = _ready()
    claim, condition = _fired_and_lifted(dep)

    for _ in range(3):
        result = _evaluate(dep)
        assert (result["still_fired_count"], result["evaluation_failed_count"]) == (1, 0)

    condition.refresh_from_db()
    assert (condition.state, condition.last_error) == (State.FIRED, "")
    assert _open_retests(dep, claim).count() == 1


# ---- the legal axis: one rule, whether the carry ran live or 0037 replayed it


def _ruling_after_its_version_closed(re_derive):
    """The adversary's history: a person rules v1 material (STALE); a re-derive closes
    v1 and opens v2; the person then rules again ON V1 -- the version they had open --
    not material (CURRENT)."""
    import datetime

    from assurance.legal import record_materiality_decision
    from assurance.models import LegalObligation

    dep = _derived_ready()
    gdpr = LegalObligation.objects.create(
        jurisdiction="EU", authority_tier=LegalObligation.AuthorityTier.REGULATION, source=f"GDPR-{dep.pk}",
        source_version="1", operative_date=datetime.date(2026, 1, 1),
    )
    gdpr.deployments.add(dep)
    person = _user()
    v1 = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    record_materiality_decision(v1, gdpr, decided_by=person, material=True, rationale="material")
    v2 = re_derive(dep, v1)
    v1 = AssuranceClaim.objects.get(pk=v1.pk)
    record_materiality_decision(v1, gdpr, decided_by=person, material=False, rationale="reviewed again: not material")
    return dep, v1, v2


def _live_re_derive(dep, v1):
    DataBoundary.objects.filter(deployment=dep).update(allowed_regions=["eu-west-1", "eu-central-1"])
    derive_claims(Deployment.objects.get(pk=dep.pk))
    return _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)


def test_a_ruling_made_on_a_version_after_it_closed_is_not_carried_live_or_by_0037():
    """A ruling applies to the version it was made on and is carried at the close
    (legal.ruling_for_next_version). The live code left v2 legally stale; 0037,
    replaying one time order across every version, carried the later ruling on v1
    onto v2 and read it legally current -- two answers from one history."""
    dep, v1, live = _ruling_after_its_version_closed(_live_re_derive)
    assert v1.legal_status == LegalStatus.CURRENT
    live.refresh_from_db()
    assert live.legal_status == LegalStatus.STALE

    dep, v1, migrated = _ruling_after_its_version_closed(_next_version)
    assert migrated.legal_status == LegalStatus.NOT_ASSESSED
    _run_data_steps("0037_carry_watches_and_legal_rulings")
    migrated.refresh_from_db()
    assert migrated.legal_status == LegalStatus.STALE
    # And the running code reads -- and carries -- the same.
    from assurance.legal import carried_legal_statuses, carry_rulings_to_current

    dep2, _v1, unrepaired = _ruling_after_its_version_closed(_next_version)
    assert carried_legal_statuses(dep2.pk, [unrepaired]) == {unrepaired.pk: LegalStatus.STALE}
    assert carry_rulings_to_current(dep2) == 1
    unrepaired.refresh_from_db()
    assert unrepaired.legal_status == LegalStatus.STALE


_T0 = timezone.now().replace(microsecond=0)


def _at(minutes):
    return _T0 + timezone.timedelta(minutes=minutes)


#: Histories as ``(stored, closed_at, moves)`` per version, oldest first -- what the
#: record says, however it came about -- and the status the carry leaves the last in.
_HISTORIES = [
    ("a ruling carried", [
        ("legally_stale", _at(2), [(_at(1), "set", "legally_stale")]),
        ("legally_not_assessed", None, []),
    ], "legally_stale"),
    ("a ruling on v1 after it closed", [
        ("legally_current", _at(2), [(_at(1), "set", "legally_stale"), (_at(3), "set", "legally_current")]),
        ("legally_not_assessed", None, []),
    ], "legally_stale"),
    ("a flag after a carried ruling", [
        ("legally_stale", _at(2), [(_at(1), "set", "legally_stale")]),
        ("legal_review_pending", None, [(_at(3), "flag", None)]),
    ], "legally_stale"),
    ("a person's later ruling on the current version", [
        ("legally_stale", _at(2), [(_at(1), "set", "legally_stale")]),
        ("legal_review_pending", None, [(_at(3), "set", "legally_current"), (_at(4), "flag", None)]),
    ], "legal_review_pending"),
    ("a ruling and a flag in one instant", [
        ("legally_stale", _at(2), [(_at(1), "set", "legally_stale")]),
        ("legally_not_assessed", None, [(_at(3), "set", "legally_current"), (_at(3), "flag", None)]),
    ], "legal_review_pending"),
    ("a status the record does not explain", [
        ("legally_stale", _at(2), []),
        ("legally_not_assessed", _at(4), []),
        ("legal_review_pending", None, []),
    ], "legally_stale"),
]


@pytest.mark.parametrize(("history", "expected"), [h[1:] for h in _HISTORIES], ids=[h[0] for h in _HISTORIES])
def test_the_running_code_and_0037_replay_one_history_to_one_status(history, expected):
    """Both paths, over the same histories: the running code's replay
    (legal.replay_lineage) and the one 0037 spells for itself. They disagreed on a
    ruling recorded on a version after it closed; nothing held them together."""
    from assurance.legal import _EVENT, _RULING, replay_lineage

    migration = _migration("0037_carry_watches_and_legal_rulings")
    # A moment's ruling is replayed before its event, on both paths.
    ordered = [
        (stored, closed, sorted(moves, key=lambda m: (m[0], _RULING if m[1] == "set" else _EVENT)))
        for stored, closed, moves in history
    ]
    assert replay_lineage(ordered) == expected
    assert migration._replay_lineage(ordered) == expected
    assert (migration._RULING, migration._EVENT) == (_RULING, _EVENT)


@pytest.mark.parametrize("state", [State.PENDING, State.FIRED, State.UNOBSERVABLE, State.EVALUATION_FAILED])
def test_the_re_derive_itself_carries_every_live_watch_to_the_new_version(state):
    """At the supersede, not later: the repair that converges what a release that did
    not carry left behind runs only where a write is next seen, and this release's
    own re-derive must leave nothing for it."""
    dep = _derived_ready()
    claim, condition = _training_watched(dep)
    LatentCondition.objects.filter(pk=condition.pk).update(state=state)
    DataBoundary.objects.filter(deployment=dep).update(allowed_regions=["eu-west-1", "eu-central-1"])

    derive_claims(Deployment.objects.get(pk=dep.pk))

    current = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    assert current.pk != claim.pk
    condition.refresh_from_db()
    assert (condition.state, condition.claim_id) == (state, current.pk)


# ---------------------------------------------------------------------------
# Round 4 of #105: a recompute by the release before that moves nothing is still
# recognised; the watches it never evaluates are evaluated where it is recognised;
# versions are read in the order the re-derives made them; and the plan reads what
# the decision reads.
# ---------------------------------------------------------------------------


def _recomputed_by_the_release_before(dep):
    """The release before recomputing after one of its writes, by ITS rules. They read
    the same decision, so the revision, the transition log and the policy stamp stay
    where they are; the one column it writes on every recompute is the keyring, which
    it writes bare (decision._KEYRING_MARK)."""
    from assurance import observed_outcomes

    Deployment.objects.filter(pk=dep.pk).update(decision_keyring=observed_outcomes.keyring_fingerprint())


def test_a_ruling_the_release_before_records_without_moving_its_decision_is_not_published_as_ready():
    """The adversary's gap. The release before records a person's ruling that a claim
    is legally stale, and recomputes under rules that do not read the legal axis:
    READY, at the revision it stood at, the stamp untouched. The stamp named this
    release's rules at that revision, so every publishing read -- the receipt, the
    detail, read_decision -- went on publishing READY while decision support said
    needs more evidence, with nothing to bound how long."""
    from assurance.decision import current_decision
    from assurance.legal import record_materiality_decision

    dep = _derived_ready()
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.READY
    row = Deployment.objects.values_list("decision", "decision_revision", "decision_policy")
    before = row.get(pk=dep.pk)
    gdpr, _ai_act = _obligations(dep)
    record_materiality_decision(
        _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY), gdpr, decided_by=_user(), material=True,
        rationale="the Art. 28 change is material",
    )
    _recomputed_by_the_release_before(dep)  # its rules do not read the legal axis: READY, unmoved
    assert row.get(pk=dep.pk) == before

    support = decision_support(Deployment.objects.get(pk=dep.pk))["decision"]
    assert support == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == support
    from assurance.revision import read_decision

    assert read_decision(Deployment.objects.get(pk=dep.pk))["decision"] == support
    # Recomputed by this release, the next read is the one with nothing to redo.
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    with CaptureQueriesContext(connection) as ctx:
        assert current_decision(Deployment.objects.get(pk=dep.pk)) == support
    assert len(ctx.captured_queries) <= 3, [q["sql"][:80] for q in ctx.captured_queries]


def test_a_migrate_recomputes_a_decision_the_release_before_recomputed_to_the_same_answer(
    django_capture_on_commit_callbacks,
):
    """Not only the first publishing read: the migrate after the rollout finds the
    keyring column that release rewrote bare, and recomputes it, with no stamp to
    clear by hand."""
    from django.core.management.sql import emit_post_migrate_signal

    from assurance.decision import stamped_in_force
    from assurance.legal import record_materiality_decision

    dep = _derived_ready()
    gdpr, _ai_act = _obligations(dep)
    record_materiality_decision(
        _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY), gdpr, decided_by=_user(), material=True,
        rationale="the Art. 28 change is material",
    )
    _recomputed_by_the_release_before(dep)

    with django_capture_on_commit_callbacks(execute=True):
        emit_post_migrate_signal(verbosity=0, interactive=False, db="default")

    fresh = Deployment.objects.get(pk=dep.pk)
    assert fresh.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert stamped_in_force(fresh)


def test_a_watch_a_write_of_the_release_before_made_true_is_evaluated_at_the_first_read():
    """The release before evaluates no watch. A tool it recorded that a watch here
    names left the watch pending, and its recompute after moved nothing. Recognised
    as that release's recompute, the decision was recomputed here -- and read the
    watch as still not true: READY, until some later write of this release's."""
    from assurance.decision import current_decision

    dep = _derived_ready()
    condition = _declare(_claim(dep), kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    with _committed():
        pass  # what the set-up scheduled runs first
    with signals.refresh_deferred(dep.pk):  # the release before's write: its refresh evaluates nothing
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
            classification=Asset.Classification.KNOWN, assessed_at=timezone.now(),
        )
    _recomputed_by_the_release_before(dep)
    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING

    with _committed():
        current_decision(Deployment.objects.get(pk=dep.pk))

    assert LatentCondition.objects.get(pk=condition.pk).state == State.FIRED
    support = decision_support(Deployment.objects.get(pk=dep.pk))["decision"]
    assert support == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == support


def test_the_migrate_after_the_rollout_evaluates_a_watch_the_release_before_made_true(
    django_capture_on_commit_callbacks,
):
    """A write the release before recomputes nothing after -- the data boundary, a
    provider's profile -- leaves no mark on the row, so no read recognises it. The
    remedy after the rollout (the stamp cleared, then `migrate`) recomputed every
    decision without evaluating a watch, and read one that write made true as still
    not true."""
    from django.core.management.sql import emit_post_migrate_signal

    from assurance.decision import stamped_in_force

    dep = _derived_ready()
    _claim_, condition = _training_watched(dep)
    with _committed():
        pass  # what the set-up scheduled runs first
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)  # the release before's write
    Deployment.objects.filter(pk=dep.pk).update(decision_policy=None)  # the remedy: the stamp cleared, then

    with django_capture_on_commit_callbacks(execute=True):
        emit_post_migrate_signal(verbosity=0, interactive=False, db="default")

    assert LatentCondition.objects.get(pk=condition.pk).state == State.FIRED
    fresh = Deployment.objects.get(pk=dep.pk)
    assert fresh.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert stamped_in_force(fresh)


def test_a_ruling_the_release_before_dropped_still_caps_after_it_flags_the_version_for_review():
    """Its re-derive opened the new version "not assessed"; a later obligation then
    flagged it for review (pending). The carry reads a pending version too: a flag is
    not a ruling, and the person's ruling on the version before still stands."""
    from assurance.decision import current_decision
    from assurance.legal import flag_for_materiality_review, record_materiality_decision

    dep = _derived_ready()
    gdpr, ai_act = _obligations(dep)
    claim = _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY)
    record_materiality_decision(claim, gdpr, decided_by=_user(), material=True, rationale="material")
    current = _re_derived_by_the_release_before(dep, claim)  # opened "not assessed"
    flag_for_materiality_review(ai_act)  # not assessed -> pending
    current.refresh_from_db()
    assert current.legal_status == LegalStatus.REVIEW_PENDING

    assert [c.pk for c in claim_decision_signal(Deployment.objects.get(pk=dep.pk))["legally_stale"]] == [current.pk]
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_watch_a_publishing_read_carries_is_evaluated_once_the_read_commits():
    """The first publishing read of the release before's decision carries the watch it
    left on the version it closed -- and a watch carried has not been read against the
    current version: the refresh that reads it is scheduled for once the read commits."""
    from assurance.decision import current_decision

    dep = _derived_ready()
    claim, condition = _training_watched(dep)
    with _committed():
        pass  # what the set-up scheduled runs first
    with signals.refresh_deferred(dep.pk):  # the release before's writes: its refresh is not this one's
        _re_derived_by_the_release_before(dep, claim)
    DataBoundary.objects.filter(deployment=dep).update(training_allowed=True)  # true, and nothing evaluated it

    with _committed():
        current_decision(Deployment.objects.get(pk=dep.pk))

    condition.refresh_from_db()
    assert condition.state == State.FIRED
    assert condition.claim_id == _claim(dep, AssuranceClaim.ClaimType.DATA_BOUNDARY).pk


def test_a_clock_that_stepped_back_between_two_re_derives_reorders_neither_replay():
    """Two re-derives by the release before on two hosts, the second 30 s behind the
    first. By `valid_from` the versions read v1, v3, v2: the lineage ended on a closed
    version, the running code carried nothing, and 0037 -- walking `superseded_by` --
    read v3 legally stale. Both now walk the versions in the order they were made."""
    import datetime

    from django.db import transaction

    from assurance.legal import carried_legal_statuses
    from assurance.models import LegalObligation, MaterialityDecision

    owner = _user()
    dep = Deployment.objects.create(name="order", owner=owner)
    obligation = LegalObligation.objects.create(
        jurisdiction="EU", authority_tier=LegalObligation.AuthorityTier.REGULATION, source="GDPR-order",
        source_version="1", operative_date=datetime.date(2026, 1, 1),
    )
    t = timezone.now() - datetime.timedelta(hours=1)

    def version(n, valid_from, valid_to, legal):
        return AssuranceClaim.objects.create(
            deployment=dep, claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY, statement="s", fingerprint="fp",
            system_fingerprint=f"s{n}", policy_version="p", environment=dep.environment,
            status=Status.VERIFIED, legal_status=legal, valid_from=valid_from, valid_to=valid_to,
            effective_from=valid_from,
        )

    minutes = datetime.timedelta(minutes=1)
    v1 = version(1, t, t + 10 * minutes, LegalStatus.STALE)
    v2 = version(2, t + 10 * minutes, t + 9.5 * minutes, LegalStatus.NOT_ASSESSED)
    v3 = version(3, t + 9.5 * minutes, None, LegalStatus.NOT_ASSESSED)
    AssuranceClaim.objects.filter(pk=v1.pk).update(superseded_by=v2)
    AssuranceClaim.objects.filter(pk=v2.pk).update(superseded_by=v3)
    ruling = MaterialityDecision.objects.create(claim=v1, obligation=obligation, decided_by=owner, material=True, rationale="m")
    MaterialityDecision.objects.filter(pk=ruling.pk).update(decided_at=t + 5 * minutes)

    live = carried_legal_statuses(dep.pk, [AssuranceClaim.objects.get(pk=v3.pk)]).get(v3.pk, LegalStatus.NOT_ASSESSED)
    with transaction.atomic():
        undo = transaction.savepoint()
        _run_data_steps("0037_carry_watches_and_legal_rulings")
        by_0037 = AssuranceClaim.objects.get(pk=v3.pk).legal_status
        transaction.savepoint_rollback(undo)

    assert by_0037 == LegalStatus.STALE
    assert live == by_0037
    assert [c.pk for c in claim_decision_signal(Deployment.objects.get(pk=dep.pk))["legally_stale"]] == [v3.pk]


def test_the_plan_reads_the_legal_carry_and_an_unread_condition_left_by_the_release_before():
    """The plan read only a fired condition's hold of the three things the decision
    reads through the release before's writes: this claim, legally stale by the carry
    and with a watch nobody can read, sat in still_current under "No claim needs
    revalidation" while decision support said needs more evidence."""
    from assurance.revalidation import plan_revalidation

    dep = _derived_ready()
    claim, condition = _ruled_stale_and_watched(dep)
    current = _re_derived_by_the_release_before(dep, claim)
    LatentCondition.objects.filter(pk=condition.pk).update(state=State.EVALUATION_FAILED)
    support = decision_support(Deployment.objects.get(pk=dep.pk))
    assert support["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert [c["uuid"] for c in support["claims"]["legally_stale"]] == [str(current.uuid)]

    plan = plan_revalidation(Deployment.objects.get(pk=dep.pk))

    assert str(current.uuid) in [w["claim_uuid"] for w in plan["required"]]
    assert str(current.uuid) not in [w["claim_uuid"] for w in plan["still_current"]]
    assert not plan["note"].startswith("No claim needs revalidation")


@pytest.mark.parametrize("cause", ["a-legal-ruling", "a-watch-nobody-can-read"])
def test_the_plan_names_the_work_for_each_thing_the_decision_is_held_back_by(cause):
    from assurance.revalidation import plan_revalidation

    dep = _derived_ready()
    if cause == "a-legal-ruling":
        claim, _condition = _ruled_stale_and_watched(dep)
        said = "legally stale"
    else:
        claim, condition = _training_watched(dep)
        LatentCondition.objects.filter(pk=condition.pk).update(state=State.UNOBSERVABLE, fired_observation="gone")
        said = "cannot be read now"
    assert decision_support(Deployment.objects.get(pk=dep.pk))["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE

    plan = plan_revalidation(Deployment.objects.get(pk=dep.pk))

    required = {w["claim_uuid"]: w for w in plan["required"]}
    assert str(claim.uuid) in required and said in required[str(claim.uuid)]["reason"]
    assert "No claim needs revalidation" not in plan["note"]
