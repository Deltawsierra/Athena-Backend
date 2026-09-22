"""Phase 2 item 9 — name the exact future change that would break a safe claim.

The roadmap's need, and the direction is the whole point:

> distinct from ``ripple.py``'s blast-radius assessment... This is the opposite
> direction: a claim that is safe *today* because a specific precondition doesn't
> hold (e.g. "exfiltration path X is contained by the absence of external-write
> permission") should be able to name that precondition explicitly and get
> invalidated proactively the moment it changes — not reactively discovered after
> the fact by generic drift detection.

And the bar, in two halves, both tested here:

1. *a claim with a declared invalidating condition is proven to flip to STALE and
   trigger a retest the instant that specific condition changes, in a test that
   changes only that condition and nothing else*;
2. *the mechanism never claims to predict an unnamed future attack — only a
   specific, declared precondition*.

The second half is the one that is easy to fake and hard to keep. It is tested
three ways: an unnamed change fires nothing; a condition that already holds is
refused rather than stored (or it would fire at once and look prescient for
reporting the past); and a subject we can no longer read goes UNOBSERVABLE rather
than quietly reading as "still safe".
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance.latent import (
    LatentConditionRefused,
    Unobservable,
    declare_condition,
    evaluate_conditions,
    latent_posture,
    observe,
    withdraw_condition,
)
from assurance.models import (
    Asset,
    AssuranceClaim,
    ClaimEvent,
    DataBoundary,
    Deployment,
    LatentCondition,
    Provider,
    ProviderAssertion,
    RetestRequirement,
)

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
Kind = LatentCondition.Kind
State = LatentCondition.State


def _user(name="analyst"):
    return User.objects.create_user(
        username=f"{name}-{User.objects.count()}", password="x", role=User.Roles.ANALYST
    )


def _deployment(name="checkout-assistant"):
    return Deployment.objects.create(name=name, owner=_user("owner"))


def _asset(
    dep, *, kind, name, classification=Asset.Classification.KNOWN, metadata=None
):
    return Asset.objects.create(
        deployment=dep,
        kind=kind,
        classification=classification,
        name=name,
        identifier=name,
        metadata=metadata or {},
    )


def _claim(dep, *, fingerprint="fp-1", status=Status.SUPPORTED):
    return AssuranceClaim.objects.create(
        deployment=dep,
        claim_type=AssuranceClaim.ClaimType.EFFECTIVE_ACCESS,
        statement="no principal can write outside the deployment",
        fingerprint=fingerprint,
        system_fingerprint="sysfp",
        policy_version="pol",
        environment=dep.environment,
        status=status,
    )


def _contained_deployment():
    """The roadmap's own example: an agent whose exfiltration path is contained by
    the absence of a code-execution capability."""
    dep = _deployment()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", metadata={"tools": ["reader"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="reader", metadata={"permissions": ["read"]})
    return dep


def _contained(dep=None):
    dep = dep or _contained_deployment()
    claim = _claim(dep)
    condition = declare_condition(
        claim,
        kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
        subject="assistant",
        expected="code_execution",
        description=(
            "The exfiltration path is contained only by the assistant having no "
            "way to run code. The moment it gains one, this claim is wrong."
        ),
        declared_by=_user("counsel"),
    )
    return dep, claim, condition


def _grant_code_execution(dep):
    """Change EXACTLY the named precondition and nothing else."""
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", metadata={"permissions": ["exec"]})
    agent = dep.assets.get(name="assistant")
    agent.metadata = {"tools": ["reader", "shell"]}
    agent.save(update_fields=["metadata"])


# ---------------------------------------------------------------------------
# The bar, first half: it fires the instant the named condition changes
# ---------------------------------------------------------------------------


def test_the_claim_flips_to_stale_the_instant_the_named_condition_becomes_true():
    dep, claim, condition = _contained()

    # Nothing has changed yet: declared, watching, claim untouched.
    before = evaluate_conditions(dep)
    claim.refresh_from_db()
    condition.refresh_from_db()
    assert before["fired_count"] == 0
    assert condition.state == State.PENDING
    assert claim.status == Status.SUPPORTED

    _grant_code_execution(dep)

    after = evaluate_conditions(dep)
    claim.refresh_from_db()
    condition.refresh_from_db()
    assert after["fired_count"] == 1
    assert condition.state == State.FIRED
    assert claim.status == Status.STALE


def test_firing_opens_a_retest_whose_reason_names_the_condition():
    """Not "the fingerprint changed". An operator reading the obligation has to
    learn WHICH declared precondition gave way, or the proactive half of this is
    worth nothing over generic drift."""
    dep, claim, condition = _contained()
    _grant_code_execution(dep)

    evaluate_conditions(dep)

    requirement = RetestRequirement.objects.get(claim__fingerprint=claim.fingerprint)
    assert "exfiltration path is contained" in requirement.reason
    assert "code_execution" in requirement.reason
    assert "assistant" in requirement.reason
    condition.refresh_from_db()
    assert condition.fired_requirement_id == requirement.pk


def test_firing_records_what_was_seen_and_what_the_baseline_was():
    """A retest that cannot be defended without re-deriving the world is a retest
    somebody will argue with."""
    dep, _claim_obj, condition = _contained()
    baseline = condition.baseline_observation
    assert "code_execution" not in baseline

    _grant_code_execution(dep)
    evaluate_conditions(dep)

    condition.refresh_from_db()
    assert "code_execution" in condition.fired_observation
    assert condition.baseline_observation == baseline
    assert condition.fired_at is not None


def test_the_claims_own_lifecycle_carries_the_named_condition():
    dep, claim, _condition = _contained()
    _grant_code_execution(dep)

    evaluate_conditions(dep)

    notes = [e.note for e in ClaimEvent.objects.filter(claim=claim)]
    assert any("declared invalidating condition came true" in n for n in notes)


def test_evaluating_twice_neither_re_fires_nor_opens_a_second_obligation():
    dep, claim, _condition = _contained()
    _grant_code_execution(dep)

    first = evaluate_conditions(dep)
    second = evaluate_conditions(dep)

    assert first["fired_count"] == 1
    assert second["fired_count"] == 0
    assert (
        RetestRequirement.objects.filter(claim__fingerprint=claim.fingerprint).count()
        == 1
    )


# ---------------------------------------------------------------------------
# The bar, second half: it predicts nothing
# ---------------------------------------------------------------------------


def test_a_change_nobody_named_fires_nothing_here():
    """The mechanism is a subscription, not a forecast. A real change that no
    declared condition covers produces nothing from this module — generic drift
    detection is the net for that, and the two stay separate on purpose."""
    dep, claim, condition = _contained()

    # A genuine, material change: a brand-new unmanaged data store appears. No
    # declared condition mentions it.
    _asset(
        dep,
        kind=Asset.Kind.DATA_STORE,
        name="scratch-bucket",
        classification=Asset.Classification.UNMANAGED,
    )

    result = evaluate_conditions(dep)
    claim.refresh_from_db()
    condition.refresh_from_db()
    assert result["fired_count"] == 0
    assert condition.state == State.PENDING
    assert claim.status == Status.SUPPORTED


def test_a_condition_that_already_holds_is_refused_not_stored():
    """Otherwise the register fires the moment it is created and reads as a
    prediction come true, when it was a present fact nobody had checked."""
    dep = _contained_deployment()
    _grant_code_execution(dep)
    claim = _claim(dep)

    with pytest.raises(LatentConditionRefused) as exc:
        declare_condition(
            claim,
            kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
            subject="assistant",
            expected="code_execution",
            description="watch for code execution",
        )
    assert "already holds" in str(exc.value)
    assert LatentCondition.objects.count() == 0


def test_the_result_says_out_loud_that_zero_fired_is_not_an_all_clear():
    """A zero on a dashboard reads as "safe" unless something stops it, so the
    payload carries the disclaimer on every call. Each clause is pinned separately:
    a version of this test that checked one phrase let a mutation rewrite the rest
    of the note and survive."""
    dep, _claim_obj, _cond = _contained()
    result = evaluate_conditions(dep)
    assert result["fired_count"] == 0
    note = result["note"]
    assert "only conditions somebody declared" in note
    assert "nothing about changes nobody named" in note
    assert "not a guarantee that it will not" in note


# ---------------------------------------------------------------------------
# Unobservable is not safe
# ---------------------------------------------------------------------------


def test_a_subject_we_can_no_longer_read_goes_unobservable_not_pending():
    """The silent zero, in its natural habitat: the principal is gone, so the
    capability check finds nothing, and "nothing found" would read as "still
    contained" unless something stops it."""
    dep, _claim_obj, condition = _contained()

    dep.assets.filter(name="assistant").delete()

    result = evaluate_conditions(dep)
    condition.refresh_from_db()
    assert condition.state == State.UNOBSERVABLE
    assert condition.state != State.PENDING
    assert result["unobservable_count"] == 1
    assert result["still_pending_count"] == 0


def test_an_unobservable_condition_does_not_flip_the_claim_either():
    """Losing sight of a precondition is a coverage problem, not evidence that it
    fired. It must not manufacture a retest any more than it manufactures safety."""
    dep, claim, _condition = _contained()
    dep.assets.filter(name="assistant").delete()

    evaluate_conditions(dep)

    claim.refresh_from_db()
    assert claim.status == Status.SUPPORTED
    assert not RetestRequirement.objects.filter(claim=claim).exists()


def test_a_missing_asset_is_unobservable_rather_than_still_managed():
    dep = _deployment()
    _asset(dep, kind=Asset.Kind.TOOL, name="reader")
    claim = _claim(dep)
    condition = declare_condition(
        claim,
        kind=Kind.ASSET_BECOMES_UNMANAGED,
        subject="reader",
        description="the reader tool falling out of management would break this",
    )

    dep.assets.filter(name="reader").delete()

    with pytest.raises(Unobservable):
        observe(condition, dep)


def test_a_missing_boundary_is_unobservable_rather_than_permissive():
    dep = _deployment()
    DataBoundary.objects.create(deployment=dep, training_allowed=False)
    claim = _claim(dep)
    condition = declare_condition(
        claim,
        kind=Kind.BOUNDARY_ALLOWS,
        subject="training",
        description="the boundary starting to permit training would break this",
    )

    dep.data_boundary.delete()
    dep.refresh_from_db()

    with pytest.raises(Unobservable):
        observe(condition, dep)


def test_an_absent_asset_is_a_real_negative_for_asset_appears():
    """The one kind where absence IS the observation: the asset set is enumerable,
    so "no asset by that name" is a reading, not a failure to look. Conflating this
    with the unobservable cases in either direction would be wrong."""
    dep = _deployment()
    claim = _claim(dep)
    condition = declare_condition(
        claim,
        kind=Kind.ASSET_APPEARS,
        subject="shadow-exporter",
        description="a shadow exporter appearing would break this claim",
    )
    holds, observation = observe(condition, dep)
    assert holds is False
    assert "0 asset(s)" in observation


def test_the_posture_surfaces_lost_coverage_at_the_top_level():
    dep, _claim_obj, _condition = _contained()
    dep.assets.filter(name="assistant").delete()
    evaluate_conditions(dep)

    posture = latent_posture(dep)
    assert posture["coverage_lost"] == 1
    assert posture["watching"] == 0
    assert "unwatched, not safe" in posture["note"]


def test_the_posture_never_blends_the_three_numbers():
    dep = _contained_deployment()
    claim_a = _claim(dep, fingerprint="a")
    claim_b = _claim(dep, fingerprint="b")
    declare_condition(
        claim_a,
        kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
        subject="assistant",
        expected="code_execution",
        description="a",
    )
    declare_condition(
        claim_b,
        kind=Kind.ASSET_APPEARS,
        subject="shadow-exporter",
        description="b",
    )

    posture = latent_posture(dep)
    assert posture["watching"] == 2
    assert posture["fired"] == 0
    assert posture["coverage_lost"] == 0
    assert posture["declared"] == 2
    # Three separate numbers, and no single score anywhere in the payload.
    assert "score" not in posture
    assert "percent" not in posture


# ---------------------------------------------------------------------------
# A declaration has to be a named precondition, not a worry
# ---------------------------------------------------------------------------


def test_a_condition_without_a_subject_is_refused():
    claim = _claim(_contained_deployment())
    with pytest.raises(LatentConditionRefused) as exc:
        declare_condition(
            claim,
            kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
            subject="   ",
            expected="code_execution",
            description="something bad",
        )
    assert "subject" in str(exc.value)


def test_a_condition_without_a_description_is_refused():
    claim = _claim(_contained_deployment())
    with pytest.raises(LatentConditionRefused) as exc:
        declare_condition(
            claim,
            kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
            subject="assistant",
            expected="code_execution",
            description="  ",
        )
    assert "description" in str(exc.value)


def test_a_kind_this_build_cannot_evaluate_is_refused():
    """A condition nothing can check is worse than no condition: it reads as
    covered while covering nothing."""
    claim = _claim(_contained_deployment())
    with pytest.raises(LatentConditionRefused) as exc:
        declare_condition(
            claim,
            kind="the_vibe_shifts",
            subject="assistant",
            description="a general sense of unease",
        )
    assert "evaluate" in str(exc.value)


def test_a_kind_that_needs_an_expected_value_is_refused_without_one():
    claim = _claim(_contained_deployment())
    with pytest.raises(LatentConditionRefused):
        declare_condition(
            claim,
            kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
            subject="assistant",
            description="the assistant gaining something",
        )


def test_a_condition_whose_subject_cannot_be_read_today_is_refused():
    """We cannot establish that it does not hold, so we cannot honestly call it
    latent — a different refusal from "it already holds", and both matter."""
    dep = _contained_deployment()
    claim = _claim(dep)
    with pytest.raises(LatentConditionRefused) as exc:
        declare_condition(
            claim,
            kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
            subject="a-principal-that-does-not-exist",
            expected="code_execution",
            description="watch a principal nobody has",
        )
    assert "cannot establish" in str(exc.value)


def test_the_same_declaration_twice_is_one_watch():
    from django.db import IntegrityError, transaction

    dep, claim, condition = _contained()
    with pytest.raises(IntegrityError), transaction.atomic():
        LatentCondition.objects.create(
            deployment=dep,
            claim=claim,
            kind=condition.kind,
            subject=condition.subject,
            expected=condition.expected,
            description="again",
        )


def test_the_declaration_uniqueness_is_declared_on_the_model_too():
    """The test database is built from the MIGRATION, so deleting the constraint
    from the model changes nothing here and the test above still passes. Asserting
    it on the model is what makes the two unable to drift apart — and
    `makemigrations --check` in CI catches the other direction."""
    names = {c.name for c in LatentCondition._meta.constraints}
    assert "uq_latent_condition_declaration" in names
    constraint = next(
        c
        for c in LatentCondition._meta.constraints
        if c.name == "uq_latent_condition_declaration"
    )
    assert tuple(constraint.fields) == ("claim", "kind", "subject", "expected")


# ---------------------------------------------------------------------------
# Scope: whose claims this touches
# ---------------------------------------------------------------------------


def test_a_superseded_claim_version_is_never_fired_on():
    """History does not get invalidated. The condition stays as it was rather than
    firing against a version nobody acts on."""
    dep = _contained_deployment()
    claim = _claim(dep)
    condition = declare_condition(
        claim,
        kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
        subject="assistant",
        expected="code_execution",
        description="contained by the absence of code execution",
    )
    from django.utils import timezone

    claim.valid_to = timezone.now()
    claim.save(update_fields=["valid_to"])
    _grant_code_execution(dep)

    result = evaluate_conditions(dep)

    condition.refresh_from_db()
    assert result["fired_count"] == 0
    assert condition.state == State.PENDING


def test_a_revoked_claim_is_never_fired_on():
    """A human withdrawal is not invalidated — the same rule invalidation.py keeps,
    kept here rather than re-decided."""
    dep = _contained_deployment()
    claim = _claim(dep, status=Status.SUPPORTED)
    declare_condition(
        claim,
        kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
        subject="assistant",
        expected="code_execution",
        description="contained by the absence of code execution",
    )
    claim.status = Status.REVOKED
    claim.save(update_fields=["status"])
    _grant_code_execution(dep)

    result = evaluate_conditions(dep)

    claim.refresh_from_db()
    assert result["fired_count"] == 0
    assert claim.status == Status.REVOKED


def test_a_withdrawn_condition_stops_firing_but_is_kept():
    """A watch that vanishes leaves no trace that it ever existed, which is how a
    gap becomes invisible."""
    dep, claim, condition = _contained()
    withdraw_condition(condition, note="superseded by a real fix")
    _grant_code_execution(dep)

    result = evaluate_conditions(dep)

    condition.refresh_from_db()
    claim.refresh_from_db()
    assert result["fired_count"] == 0
    assert condition.state == State.WITHDRAWN
    assert LatentCondition.objects.filter(pk=condition.pk).exists()
    assert claim.status == Status.SUPPORTED


def test_conditions_on_another_deployment_are_not_evaluated():
    dep_a, _claim_a, cond_a = _contained()
    dep_b = _contained_deployment()
    _grant_code_execution(dep_a)

    result = evaluate_conditions(dep_b)

    cond_a.refresh_from_db()
    assert result["fired_count"] == 0
    assert cond_a.state == State.PENDING


# ---------------------------------------------------------------------------
# The other observable kinds, each proven to read real state
# ---------------------------------------------------------------------------


def test_a_boundary_practice_flipping_fires():
    dep = _deployment()
    DataBoundary.objects.create(deployment=dep, training_allowed=False)
    claim = _claim(dep)
    declare_condition(
        claim,
        kind=Kind.BOUNDARY_ALLOWS,
        subject="training",
        description="this claim holds only while the boundary forbids training",
    )

    boundary = dep.data_boundary
    boundary.training_allowed = True
    boundary.save(update_fields=["training_allowed"])

    result = evaluate_conditions(dep)
    claim.refresh_from_db()
    assert result["fired_count"] == 1
    assert claim.status == Status.STALE


def test_a_region_being_added_to_the_boundary_fires():
    dep = _deployment()
    DataBoundary.objects.create(deployment=dep, allowed_regions=["EU"])
    claim = _claim(dep)
    declare_condition(
        claim,
        kind=Kind.BOUNDARY_REGION_ADDED,
        subject="approved regions",
        expected="us-east-1",
        description="adding a US region would put data outside the assessed boundary",
    )

    boundary = dep.data_boundary
    boundary.allowed_regions = ["EU", "US-EAST-1"]
    boundary.save(update_fields=["allowed_regions"])

    assert evaluate_conditions(dep)["fired_count"] == 1


def test_a_named_asset_appearing_fires():
    dep = _deployment()
    claim = _claim(dep)
    declare_condition(
        claim,
        kind=Kind.ASSET_APPEARS,
        subject="shadow-exporter",
        description="a shadow exporter appearing would open an egress path",
    )

    _asset(dep, kind=Asset.Kind.DATA_STORE, name="shadow-exporter")

    assert evaluate_conditions(dep)["fired_count"] == 1


def test_an_asset_becoming_unmanaged_fires():
    dep = _deployment()
    asset = _asset(
        dep,
        kind=Asset.Kind.TOOL,
        name="reader",
        classification=Asset.Classification.APPROVED,
    )
    claim = _claim(dep)
    declare_condition(
        claim,
        kind=Kind.ASSET_BECOMES_UNMANAGED,
        subject="reader",
        description="this claim assumes the reader stays managed",
    )

    asset.classification = Asset.Classification.UNMANAGED
    asset.save(update_fields=["classification"])

    assert evaluate_conditions(dep)["fired_count"] == 1


def test_a_provider_posture_changing_fires():
    dep = _deployment()
    provider = Provider.objects.create(
        name="acme-llm", kind=Provider.Kind.MODEL_PROVIDER
    )
    ProviderAssertion.objects.create(
        provider=provider, field="trains_on_customer_data", value="no"
    )
    claim = _claim(dep)
    declare_condition(
        claim,
        kind=Kind.PROVIDER_POSTURE_CHANGES,
        subject="acme-llm",
        expected="trains_on_customer_data",
        description="this claim rests on the provider not training on customer data",
    )

    assertion = provider.assertions.get(field="trains_on_customer_data")
    assertion.value = "yes"
    assertion.save(update_fields=["value"])

    assert evaluate_conditions(dep)["fired_count"] == 1


def test_a_provider_posture_holding_still_does_not_fire():
    """The change is measured against the declared baseline, so re-reading the same
    value is not a change. Without this the kind would fire on its first run and be
    useless."""
    dep = _deployment()
    provider = Provider.objects.create(
        name="acme-llm", kind=Provider.Kind.MODEL_PROVIDER
    )
    ProviderAssertion.objects.create(
        provider=provider, field="trains_on_customer_data", value="no"
    )
    claim = _claim(dep)
    declare_condition(
        claim,
        kind=Kind.PROVIDER_POSTURE_CHANGES,
        subject="acme-llm",
        expected="trains_on_customer_data",
        description="this claim rests on the provider not training on customer data",
    )

    assert evaluate_conditions(dep)["fired_count"] == 0
    assert evaluate_conditions(dep)["fired_count"] == 0


def test_a_changed_since_baseline_kind_is_declarable_at_all():
    """A regression guard for a bug this suite found: the "did it change?" kinds
    compare a reading against the baseline recorded at declaration, and at
    declaration there is no baseline yet. Comparing against the empty string made
    every such condition unequal to it, so declare_condition refused all of them at
    birth as "already holds" — a whole category of condition that could never be
    watched, with an error message that pointed the wrong way."""
    dep = _deployment()
    provider = Provider.objects.create(
        name="acme-llm", kind=Provider.Kind.MODEL_PROVIDER
    )
    ProviderAssertion.objects.create(
        provider=provider, field="trains_on_customer_data", value="no"
    )
    claim = _claim(dep)

    condition = declare_condition(
        claim,
        kind=Kind.PROVIDER_POSTURE_CHANGES,
        subject="acme-llm",
        expected="trains_on_customer_data",
        description="this claim rests on the provider not training on customer data",
    )
    assert condition.state == State.PENDING
    # The first reading established the baseline; it is not itself a change.
    assert "trains_on_customer_data" in condition.baseline_observation
    assert observe(condition, dep)[0] is False


def test_the_policy_version_changing_fires():
    dep = _deployment()
    claim = _claim(dep)
    condition = declare_condition(
        claim,
        kind=Kind.POLICY_VERSION_CHANGES,
        subject="assurance policy",
        description="this claim was judged under the policy in force today",
    )
    assert evaluate_conditions(dep)["fired_count"] == 0

    # Move only the recorded baseline, which is the same thing as the policy
    # moving underneath it, without reaching into the policy module.
    condition.refresh_from_db()
    condition.baseline_observation = "policy_version=mythos.assurance.policy/0+older"
    condition.save(update_fields=["baseline_observation"])

    assert evaluate_conditions(dep)["fired_count"] == 1


def test_a_principal_becoming_privileged_fires():
    dep = _contained_deployment()
    claim = _claim(dep)
    declare_condition(
        claim,
        kind=Kind.PRINCIPAL_BECOMES_PRIVILEGED,
        subject="assistant",
        description="this claim holds only while the assistant is unprivileged",
    )

    _grant_code_execution(dep)

    assert evaluate_conditions(dep)["fired_count"] == 1


def test_an_unwired_kind_reads_as_unobservable_not_as_safe():
    """The safety net for a kind added tomorrow. The test above proves every kind
    in today's enum is wired, which makes this branch unreachable through the enum
    — and therefore untested unless it is reached directly. A future kind whose
    observer somebody forgot must read "we cannot answer this", never "it has not
    happened"."""
    dep = _contained_deployment()
    claim = _claim(dep)
    orphan = LatentCondition(
        deployment=dep,
        claim=claim,
        kind="a_kind_from_the_future",
        subject="anything",
        description="a kind nobody wired an observer for",
    )
    with pytest.raises(Unobservable):
        observe(orphan, dep)


def test_a_condition_filed_under_the_wrong_deployment_is_not_evaluated():
    """`LatentCondition.deployment` is denormalised from `claim.deployment`, and
    nothing at the database level keeps them equal. The evaluator scopes on BOTH,
    so a row whose two disagree is evaluated under neither — rather than under
    whichever one a single filter happened to read."""
    dep_a = _contained_deployment()
    dep_b = _deployment("other")
    claim_on_a = _claim(dep_a)
    # A mismatched row, built directly: deployment B, claim on A.
    LatentCondition.objects.create(
        deployment=dep_b,
        claim=claim_on_a,
        kind=Kind.PRINCIPAL_GAINS_CAPABILITY,
        subject="assistant",
        expected="code_execution",
        description="a row whose deployment disagrees with its claim's",
        baseline_observation="principal 'assistant' holds capabilities ['tool_invocation']",
    )
    _grant_code_execution(dep_a)

    assert evaluate_conditions(dep_a)["fired_count"] == 0
    assert evaluate_conditions(dep_b)["fired_count"] == 0


def test_every_kind_in_the_vocabulary_has_an_observer():
    """Enumerate, do not spot-check. A kind added to the enum without an observer
    would be declarable-looking and permanently unevaluable."""
    from assurance.latent import _OBSERVERS

    missing = [value for value, _ in Kind.choices if value not in _OBSERVERS]
    assert missing == []


def test_no_observer_returns_false_when_it_means_it_could_not_look():
    """The rule this module lives by, asserted structurally: every observer either
    returns a real reading or raises Unobservable. None of them may return a bare
    False for 'the subject was not there' — except ASSET_APPEARS, where absence
    over an enumerable set is the reading."""
    import inspect

    from assurance import latent

    offenders = []
    for kind, observer in latent._OBSERVERS.items():
        if kind == Kind.ASSET_APPEARS:
            continue
        source = inspect.getsource(observer)
        looks_up_a_subject = (
            ".first()" in source or "for principal in" in source or "getattr(" in source
        )
        if (
            looks_up_a_subject
            and "Unobservable" not in source
            and "_boundary(" not in source
            and "_principal(" not in source
        ):
            offenders.append(kind)
    assert offenders == []
