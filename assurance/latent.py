"""Conditional / latent-risk subscription — name the exact future change that would
break a currently-safe claim, before it happens (Phase 2 item 9).

The direction matters. :mod:`assurance.ripple` computes blast radius *forward*
from something already wrong. :mod:`assurance.invalidation` notices, *afterwards*,
that a fingerprint moved. Neither can say, today, "this claim is safe only because
X does not hold, and the moment X holds it is not".

``AssuranceClaim.invalidation_conditions`` already names those preconditions, in
prose, which nothing evaluates. This module makes one checkable:

1. Somebody declares the precondition as a row, in a closed vocabulary of things
   the stored state can actually answer (:class:`~assurance.models.LatentCondition.Kind`).
2. Declaration REFUSES if the condition already holds. A latent risk that is
   already true is a present fact nobody checked, and letting it in would produce
   a mechanism that looks prescient by firing on things that had already happened.
3. :func:`evaluate_conditions` re-reads each declared precondition against current
   state. The instant one becomes true, its claim goes STALE and a retest opens
   whose reason NAMES the condition -- not "the fingerprint changed".

What it deliberately does not do
--------------------------------
**It never predicts an unnamed future.** No scoring, no inference, no "this looks
like it might". A condition nobody declared produces nothing here; generic drift
detection stays the net for everything else. A test asserts that changing
something unnamed fires nothing.

**It never reads an absence as safety.** If the subject can no longer be observed
-- the principal is gone, the boundary row was deleted -- the condition goes
UNOBSERVABLE, not "still does not hold". A precondition we have lost sight of is
a gap in coverage and is counted as one. Returning False there would be the exact
silent zero this codebase keeps finding: nothing seen, read as nothing wrong.

**PENDING is not a guarantee.** It means this one named thing has not happened as
of ``last_evaluated_at``. The posture read says so in words, because "0 fired" on
a dashboard reads as "safe" unless something stops it.
"""

from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from .graph_refs import in_graph
from . import observability as obs
from .models import AssuranceClaim, DataBoundary, LatentCondition, Provider
from .governance import is_shadow

Kind = LatentCondition.Kind
State = LatentCondition.State

logger = logging.getLogger(__name__)

#: The kinds a write to the deployment's data boundary can make true.
BOUNDARY_KINDS = frozenset({Kind.BOUNDARY_ALLOWS, Kind.BOUNDARY_REGION_ADDED})

# What a boundary practice name means. Closed, so "training" cannot silently be
# spelled three ways and match none of them.
_BOUNDARY_PRACTICES = {
    "training": "training_allowed",
    "third_party_sharing": "third_party_sharing_allowed",
}



class LatentConditionRefused(ValueError):
    """A declaration was rejected rather than stored in a shape that would lie.

    Raised when the condition is unnamed, its kind cannot be evaluated as written,
    or -- most importantly -- when it ALREADY holds. See the module docstring: a
    latent condition that is already true is not latent.
    """


class Unobservable(Exception):
    """The subject cannot be seen, so the condition has no truth value right now.

    Deliberately an exception rather than a ``False`` return. A None-or-False
    return is exactly how "we could not look" decays into "nothing found" one
    refactor later.
    """


# ---------------------------------------------------------------------------
# Observers: each answers one closed question about stored state, and raises
# Unobservable rather than guessing.
# ---------------------------------------------------------------------------


def _principal(deployment, name: str) -> dict:
    from .access import assess_effective_access

    assessment = assess_effective_access(deployment)
    for principal in assessment["principals"]:
        if principal["name"] == name:
            return principal
    raise Unobservable(f"no principal named {name!r} on this deployment")


def _observe_principal_gains_capability(condition, deployment) -> tuple[bool, str]:
    principal = _principal(deployment, condition.subject)
    held = sorted(cap["key"] for cap in principal["capabilities"])
    return condition.expected in held, (
        f"principal {condition.subject!r} holds capabilities {held or ['(none)']}"
    )


def _observe_principal_becomes_privileged(condition, deployment) -> tuple[bool, str]:
    principal = _principal(deployment, condition.subject)
    return bool(principal["privileged"]), (
        f"principal {condition.subject!r} privilege_level="
        f"{principal['privilege_level']}, privileged={principal['privileged']}"
    )


def _observe_asset_appears(condition, deployment) -> tuple[bool, str]:
    # Absence IS the observation here: the asset set is enumerable, so "no asset
    # by that name" is a real reading, not a failure to look. This is the one
    # kind where a negative is evidence.
    matches = [
        asset
        for asset in in_graph(deployment.assets.all())
        if asset.name == condition.subject or asset.identifier == condition.subject
    ]
    return bool(matches), (
        f"{len(matches)} asset(s) named or identified {condition.subject!r} "
        f"among {len(in_graph(deployment.assets.all()))} on the deployment"
    )


def _observe_asset_becomes_unmanaged(condition, deployment) -> tuple[bool, str]:
    # A retired row is no component: read as one, a tool nobody declares any more
    # answered "still known" where the rule is that a gone asset is unobservable.
    named = in_graph(deployment.assets.filter(name=condition.subject).order_by("kind", "identifier", "pk"))
    if not named:
        # NOT False. The asset this condition is about is gone, so we cannot say
        # whether it became unmanaged -- an asset that left the inventory is a
        # coverage question, not a clean bill of health.
        raise Unobservable(f"no asset named {condition.subject!r} on this deployment")
    if len(named) > 1:
        # Every component by that name, not one of them. Reading one -- the oldest
        # row, or whichever the database returned first -- made the tripwire depend
        # on row order: two tools both called "github", one flagged unmanaged, read
        # "still known" or "stopped" as the rows came back. The condition asks to
        # be told when the component stops being governed, and any of them may be it.
        shadowed = [a for a in named if is_shadow(a.classification)]
        return bool(shadowed), (
            f"{len(named)} assets named {condition.subject!r}: "
            + ", ".join(f"{a.kind} {a.identifier!r} classification={a.classification}" for a in named)
        )
    asset = named[0]
    # `is_shadow`, not a private {UNMANAGED, UNKNOWN} set.
    #
    # An operator who declares this condition is saying "tell me when this asset
    # stops being governed". A move from `known` to `high_risk` or to `retired`
    # is exactly that -- somebody looked at the component and flagged it -- and
    # the tripwire did not fire, so the person who asked to be told was not
    # told. The enum's own label has been widened to match, because a predicate
    # that means more than its label is how this defect gets made again.
    return is_shadow(asset.classification), (
        f"asset {condition.subject!r} classification={asset.classification}"
    )


def _boundary(deployment) -> DataBoundary:
    boundary = getattr(deployment, "data_boundary", None)
    if boundary is None:
        raise Unobservable("this deployment has no approved data boundary recorded")
    return boundary


def _observe_boundary_allows(condition, deployment) -> tuple[bool, str]:
    field = _BOUNDARY_PRACTICES.get(condition.subject)
    if field is None:
        raise Unobservable(
            f"{condition.subject!r} is not a boundary practice this can read"
        )
    boundary = _boundary(deployment)
    value = bool(getattr(boundary, field))
    return value, f"boundary.{field}={value}"


def _observe_boundary_region_added(condition, deployment) -> tuple[bool, str]:
    boundary = _boundary(deployment)
    regions = [str(r).strip().upper() for r in (boundary.allowed_regions or [])]
    wanted = condition.expected.strip().upper()
    return wanted in regions, f"boundary.allowed_regions={regions or ['(none)']}"


def _changed_since_baseline(condition, reading: str) -> bool:
    """Whether a reading differs from the one recorded when the condition was
    declared.

    Some kinds ask "did this change?" rather than "did this become true?", and for
    those the first reading is what ESTABLISHES the baseline -- it cannot itself be
    a change. Without this, :func:`declare_condition` probes the condition before
    any baseline exists, the empty string compares unequal to every real reading,
    and every such condition is refused at birth as "already holds". Found by the
    test that declares one, not by reading the code.
    """
    if not condition.baseline_observation:
        return False
    return reading != condition.baseline_observation


def _observe_provider_posture_changes(condition, deployment) -> tuple[bool, str]:
    providers = list(Provider.objects.filter(name=condition.subject).order_by("kind", "pk")[:2])
    if not providers:
        raise Unobservable(f"no provider named {condition.subject!r}")
    if len(providers) > 1:
        # A name is unique only within a kind. The baseline was read off one of them,
        # and `.first()` picked one by an ordering the name ties in -- so a second
        # provider by that name could turn the reading into the other one's and fire
        # on a change nobody made, or hide the one that was made.
        raise Unobservable(
            f"more than one provider is named {condition.subject!r}; which one this "
            "condition watches cannot be told"
        )
    provider = providers[0]
    assertion = provider.assertions.filter(field=condition.expected).first()
    if assertion is None:
        raise Unobservable(
            f"provider {condition.subject!r} declares nothing for field "
            f"{condition.expected!r}"
        )
    reading = f"provider {condition.subject!r} {condition.expected}={assertion.value!r}"
    # "Changed" is measured against what was observed at declaration, which is the
    # only honest reading of the word: there is no absolute "unchanged" value.
    return _changed_since_baseline(condition, reading), reading


def _observe_policy_version_changes(condition, deployment) -> tuple[bool, str]:
    from .fingerprint import policy_version

    reading = f"policy_version={policy_version(deployment)}"
    return _changed_since_baseline(condition, reading), reading


_OBSERVERS = {
    Kind.PRINCIPAL_GAINS_CAPABILITY: _observe_principal_gains_capability,
    Kind.PRINCIPAL_BECOMES_PRIVILEGED: _observe_principal_becomes_privileged,
    Kind.ASSET_APPEARS: _observe_asset_appears,
    Kind.ASSET_BECOMES_UNMANAGED: _observe_asset_becomes_unmanaged,
    Kind.BOUNDARY_ALLOWS: _observe_boundary_allows,
    Kind.BOUNDARY_REGION_ADDED: _observe_boundary_region_added,
    Kind.PROVIDER_POSTURE_CHANGES: _observe_provider_posture_changes,
    Kind.POLICY_VERSION_CHANGES: _observe_policy_version_changes,
}

# The kinds whose expected value carries the question rather than decorating it.
# Declared here so a kind added without deciding this fails loudly at declaration
# rather than quietly evaluating against an empty string.
_EXPECTED_REQUIRED = {
    Kind.PRINCIPAL_GAINS_CAPABILITY,
    Kind.BOUNDARY_REGION_ADDED,
    Kind.PROVIDER_POSTURE_CHANGES,
}


def observe(condition, deployment) -> tuple[bool, str]:
    """Read one condition against current state.

    Returns ``(holds, observation)``. Raises :class:`Unobservable` when the subject
    cannot be seen -- never a False that would pass for safety.
    """
    observer = _OBSERVERS.get(condition.kind)
    if observer is None:
        # A kind with no observer is not "does not hold". It is a declaration this
        # build cannot honour, and saying so is the only honest answer.
        raise Unobservable(f"no observer is wired for kind {condition.kind!r}")
    return observer(condition, deployment)


# ---------------------------------------------------------------------------
# Declaration
# ---------------------------------------------------------------------------


@transaction.atomic
def declare_condition(
    claim: AssuranceClaim,
    *,
    kind: str,
    subject: str,
    description: str,
    expected: str = "",
    declared_by=None,
) -> LatentCondition:
    """Declare the exact future change that would falsify this claim.

    Refuses four ways, each because storing the row would make the register read
    as covering something it does not:

    - no subject, or no description -- a precondition nobody named is a worry;
    - a kind this build has no observer for;
    - a kind that needs an ``expected`` value without one;
    - **a condition that already holds.** That is the important one. A latent risk
      that is already true is a present fact nobody checked, and a register that
      accepted it would fire immediately and look prescient for reporting the past.

    An unobservable subject is also refused, for a different reason: we cannot
    establish that the condition does not hold today, so we cannot honestly call
    it latent.
    """
    if kind not in _OBSERVERS:
        raise LatentConditionRefused(
            f"{kind!r} is not a condition kind this build can evaluate; a condition "
            "nothing can check reads as covered while covering nothing"
        )
    if not (subject or "").strip():
        raise LatentConditionRefused(
            "a latent condition needs a subject: the thing it is about, named"
        )
    if not (description or "").strip():
        raise LatentConditionRefused(
            "a latent condition needs a description: the exact future change, in "
            "the words of whoever knows why this claim is safe today"
        )
    if kind in _EXPECTED_REQUIRED and not (expected or "").strip():
        raise LatentConditionRefused(
            f"a {kind} condition needs an expected value: the capability, region or "
            "field whose arrival is the change being watched for"
        )

    deployment = claim.deployment
    probe = LatentCondition(
        deployment=deployment,
        claim=claim,
        kind=kind,
        subject=subject.strip(),
        expected=(expected or "").strip(),
        description=description.strip(),
    )
    try:
        holds, observation = observe(probe, deployment)
    except Unobservable as exc:
        raise LatentConditionRefused(
            f"cannot establish that this condition does not hold today: {exc}. A "
            "condition we cannot read now cannot be called latent"
        ) from exc
    if holds:
        raise LatentConditionRefused(
            f"this condition already holds ({observation}); it is a present fact, "
            "not a latent one, and belongs in an assessment rather than a watch list"
        )

    probe.baseline_observation = observation
    probe.state = State.PENDING
    probe.last_evaluated_at = timezone.now()
    probe.declared_by = declared_by
    probe.save()
    return probe


def withdraw_condition(
    condition: LatentCondition, *, note: str = ""
) -> LatentCondition:
    """Stop watching, visibly. The row is kept, not deleted, so the record shows
    that somebody decided to stop -- a watch that vanishes leaves no trace that it
    ever existed, which is how a gap becomes invisible."""
    condition.state = State.WITHDRAWN
    condition.fired_observation = note
    condition.save(update_fields=["state", "fired_observation", "updated_at"])
    return condition


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@transaction.atomic
def evaluate_conditions(deployment, *, actor=None, now=None) -> dict:
    """Re-read every pending condition on this deployment's current claims.

    A condition that has become true fires: its claim is moved away from a pass to
    STALE and a retest obligation opens whose reason NAMES the condition. That is
    the whole point -- an operator reading the obligation learns which declared
    precondition gave way, not that some fingerprint moved.

    A condition whose subject can no longer be read goes UNOBSERVABLE and is
    counted as a coverage loss. It is never treated as "still does not hold".

    Only CURRENT claim versions are considered, and never a human-REVOKED claim:
    a withdrawn claim is not invalidated, and a superseded version is history.
    Idempotent -- a second run neither re-fires nor opens a duplicate obligation.
    """
    from .fingerprint import compute_system_fingerprint
    from .invalidation import _has_open_requirement, _mark_stale, _open_requirement

    now = now or timezone.now()
    fired: list[str] = []
    lost: list[str] = []
    still_pending: list[str] = []

    with obs.span(
        obs.PLAN, component="evaluate_conditions", subject=str(deployment.pk)
    ):
        current_pks = set(
            AssuranceClaim.objects.filter(deployment=deployment)
            .current()
            .exclude(status=AssuranceClaim.ClaimStatus.REVOKED)
            .values_list("pk", flat=True)
        )
        # Scoped on BOTH the deployment and the current-claim set, deliberately.
        # `claim__in=current_pks` is already the stronger guard -- it is derived
        # from this deployment -- so `deployment=deployment` is redundant while the
        # denormalised column agrees with `claim.deployment`. Nothing at the
        # database level keeps those equal (Django cannot express a cross-table
        # check), so the pair is what makes a row whose two disagree evaluate under
        # neither, rather than under whichever one a single filter happened to
        # read. Removing either alone is invisible; removing both is not.
        conditions = list(
            LatentCondition.objects.filter(
                deployment=deployment, state=State.PENDING, claim__in=current_pks
            ).select_related("claim")
        )
        if not conditions:
            return _result(deployment, fired, lost, still_pending, now)

        system_fp = compute_system_fingerprint(deployment)

        for condition in conditions:
            try:
                holds, observation = observe(condition, deployment)
            except Unobservable as exc:
                condition.state = State.UNOBSERVABLE
                condition.fired_observation = str(exc)
                condition.last_evaluated_at = now
                condition.save(
                    update_fields=[
                        "state",
                        "fired_observation",
                        "last_evaluated_at",
                        "updated_at",
                    ]
                )
                lost.append(str(condition.uuid))
                continue

            condition.last_evaluated_at = now
            if not holds:
                condition.save(update_fields=["last_evaluated_at", "updated_at"])
                still_pending.append(str(condition.uuid))
                continue

            claim = condition.claim
            reason = (
                f"A declared invalidating condition came true: {condition.description} "
                f"({condition.get_kind_display()}; subject {condition.subject!r}"
                f"{f'; expected {condition.expected!r}' if condition.expected else ''}). "
                f"Observed: {observation}. Declared baseline was: "
                f"{condition.baseline_observation or '(none recorded)'}."
            )
            requirement = None
            if not _has_open_requirement(deployment, claim):
                requirement = _open_requirement(
                    deployment,
                    claim,
                    system_fp=system_fp,
                    now=now,
                    actor=actor,
                    reason=reason,
                )
            _mark_stale(claim, now)

            condition.state = State.FIRED
            condition.fired_at = now
            condition.fired_observation = observation
            condition.fired_requirement = requirement
            condition.save(
                update_fields=[
                    "state",
                    "fired_at",
                    "fired_observation",
                    "fired_requirement",
                    "last_evaluated_at",
                    "updated_at",
                ]
            )
            fired.append(str(condition.uuid))

    return _result(deployment, fired, lost, still_pending, now)


def _result(deployment, fired, lost, still_pending, now) -> dict:
    return {
        "deployment": str(deployment.uuid),
        "evaluated_at": now.isoformat(),
        "fired": fired,
        "fired_count": len(fired),
        # Counted and named separately from "pending". A condition we can no
        # longer read is not one that has not happened.
        "unobservable": lost,
        "unobservable_count": len(lost),
        "still_pending": still_pending,
        "still_pending_count": len(still_pending),
        # Said on every call so a caller cannot read a zero as an all-clear.
        "note": (
            "Fired counts only conditions somebody declared. This mechanism says "
            "nothing about changes nobody named; generic drift detection covers "
            "those. A pending condition has not happened as of this evaluation -- "
            "it is not a guarantee that it will not."
        ),
    }


def latent_posture(deployment) -> dict:
    """What is being watched for on this deployment, counted without a score.

    Three numbers, never blended. Pending is not a safety measure, fired is work
    already owed, and unobservable is watch we have lost -- each calls for
    something different, and one percentage would hide the third.
    """
    conditions = list(
        LatentCondition.objects.filter(deployment=deployment).select_related("claim")
    )
    by_state = {value: 0 for value, _ in State.choices}
    for condition in conditions:
        by_state[condition.state] = by_state.get(condition.state, 0) + 1
    # Pending on a claim nothing evaluates -- a closed version, or one a person
    # revoked -- is not watched. :func:`evaluate_conditions` reads only current,
    # unrevoked claims, and counting these as "watching" said a precondition was
    # under watch that nothing would ever read again.
    unwatched = [
        c for c in conditions if c.state == State.PENDING and not _evaluated_claim(c.claim)
    ]

    return {
        "deployment": str(deployment.uuid),
        "declared": len(conditions),
        "by_state": by_state,
        "watching": by_state.get(State.PENDING, 0) - len(unwatched),
        "fired": by_state.get(State.FIRED, 0),
        # Surfaced at the top level, not buried in by_state, because this is the
        # number that silently turns into "nothing wrong" if nobody looks.
        "coverage_lost": by_state.get(State.UNOBSERVABLE, 0),
        "unwatched": len(unwatched),
        "conditions": [condition_view(c) for c in conditions],
        "note": (
            "Watching counts named preconditions that have not happened as of each "
            "one's last evaluation. It is not a prediction and not an all-clear. "
            "coverage_lost counts conditions whose subject can no longer be read: "
            "those are unwatched, not safe. So are the ones counted as unwatched, "
            "declared on a claim nothing evaluates any more (a closed version, or one "
            "a person revoked)."
        ),
    }


def _evaluated_claim(claim) -> bool:
    """Whether :func:`evaluate_conditions` reads conditions declared on ``claim``."""
    return claim.valid_to is None and claim.status != AssuranceClaim.ClaimStatus.REVOKED


def condition_view(c: LatentCondition) -> dict:
    """One condition as the posture and the API report it."""
    return {
        "uuid": str(c.uuid),
        "claim": str(c.claim.uuid),
        "kind": c.kind,
        "kind_label": c.get_kind_display(),
        "subject": c.subject,
        "expected": c.expected,
        "description": c.description,
        "state": c.state,
        "baseline_observation": c.baseline_observation,
        "fired_observation": c.fired_observation,
        "last_evaluated_at": (
            c.last_evaluated_at.isoformat() if c.last_evaluated_at else None
        ),
    }


# ---------------------------------------------------------------------------
# In production: when a write could make a declared condition true
# ---------------------------------------------------------------------------


def fire_due_conditions(deployment, *, actor=None, now=None) -> int:
    """Evaluate ``deployment``'s pending conditions now; the number that fired.

    Called wherever the deployment's stored decision is brought current -- every
    write to what the decision reads refreshes it (:mod:`assurance.signals`, the
    API routes, scan ingest, the admin) -- and after a write to the data boundary
    or a provider's profile a pending condition names. :func:`evaluate_conditions`
    had no caller outside the tests, so a declared precondition that came true
    fired never: the claim it was declared on stayed a pass, and no retest opened.

    A condition firing marks its claim STALE and opens a retest, and the decision
    is refreshed after this, so it reads them. Never raises: it runs inside writes
    that must not fail for it -- a claim a person is revoking among them -- so a
    failure is logged, rolled back to before the evaluation, and leaves every
    condition PENDING with the ``last_evaluated_at`` of the last evaluation that
    completed, which the posture reports. Returns 0 at once, with one query, for a
    deployment nobody declared a condition on.
    """
    if not LatentCondition.objects.filter(deployment=deployment, state=State.PENDING).exists():
        return 0
    try:
        with transaction.atomic():
            return evaluate_conditions(deployment, actor=actor, now=now)["fired_count"]
    except Exception:
        logger.exception(
            "latent conditions on deployment %s were not evaluated; each keeps the "
            "last_evaluated_at of the last evaluation that completed",
            deployment.pk,
        )
        return 0


def deployments_watching_boundary(deployment_id) -> set:
    """``{deployment_id}`` if a pending condition there reads its data boundary."""
    watched = LatentCondition.objects.filter(
        deployment_id=deployment_id, state=State.PENDING, kind__in=BOUNDARY_KINDS
    ).exists()
    return {deployment_id} if watched else set()


def deployments_watching_provider(*names) -> set:
    """The deployments where a pending condition reads the profile of a provider
    called any of ``names`` -- every name the write touched, the one it had before
    a rename included, since a condition naming that one now names nothing."""
    wanted = {str(n) for n in names if n}
    if not wanted:
        return set()
    return set(
        LatentCondition.objects.filter(
            state=State.PENDING, kind=Kind.PROVIDER_POSTURE_CHANGES, subject__in=wanted
        ).values_list("deployment_id", flat=True)
    )
