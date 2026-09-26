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
4. A condition that FIRED holds its claim there. A re-derive does not read it back
   to a pass, and does not resolve its retest, while the precondition is still
   true: the watch clears only when a re-evaluation finds the subject back at its
   baseline (the condition re-arms to PENDING and its retest is resolved), or when
   a person withdraws it, which is a person accepting the state it fired on.

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
silent zero this codebase keeps finding: nothing seen, read as nothing wrong. It
is read again on every evaluation, so a subject that comes back into sight is
watched again -- and while it cannot be read, the deployment's decision is held
at "needs more evidence" (:func:`assurance.decision.claim_decision_signal`). So is
a condition whose evaluation failed (EVALUATION_FAILED): each is read in its own
savepoint, so one that raises is recorded as failed and the rest are evaluated.

**It never runs inside a stop.** Evaluation is scheduled for after the commit of
the write that could make a condition true, through the backstop in
:mod:`assurance.signals`. A claim revoke used to evaluate every condition on the
deployment inline, before the revoke could commit, and on a large graph that took
seconds. Only the write's own deployment may be evaluated inline, and only on a
write that is not a stop (a data boundary, the invalidation check, a scan ingest).

**PENDING is not a guarantee.** It means this one named thing has not happened as
of ``last_evaluated_at``. The posture read says so in words, because "0 fired" on
a dashboard reads as "safe" unless something stops it.
"""

from __future__ import annotations

import contextvars
import logging

from django.db import DatabaseError, IntegrityError, transaction
from django.utils import timezone

from .graph_refs import in_graph
from . import observability as obs
from .models import (
    LATENT_HOLDING_STATES,
    LATENT_LIVE_STATES,
    AssuranceClaim,
    ClaimEvent,
    DataBoundary,
    LatentCondition,
    Provider,
    RetestRequirement,
)
from .governance import is_shadow

Kind = LatentCondition.Kind
State = LatentCondition.State

logger = logging.getLogger(__name__)

#: One effective-access assessment per deployment per evaluation, shared by every
#: principal condition in it. Each read it afresh: a hundred principal conditions on
#: a deployment with three hundred tools took 2.3 seconds -- inside a claim revoke,
#: when evaluation still ran there. Set only for the length of one evaluation, so no
#: reading outlives the state it was taken from.
_ACCESS_READ: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "assurance_latent_access_read", default=None
)

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


class LatentConditionDuplicate(LatentConditionRefused):
    """The same watch is already declared, live, on this claim.

    A refusal like the others, and a different answer: nothing is wrong with the
    declaration, it is already in force. ``existing`` is the one that stands (None
    when it was declared concurrently and could not be read back). The route answers
    409 with it rather than 500 on the constraint.
    """

    def __init__(self, message: str, existing: LatentCondition | None = None):
        super().__init__(message)
        self.existing = existing


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

    read = _ACCESS_READ.get()
    assessment = None if read is None else read.get(deployment.pk)
    if assessment is None:
        assessment = assess_effective_access(deployment)
        if read is not None:
            read[deployment.pk] = assessment
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

    And a declaration already live on this claim -- pending, fired, unobservable or
    failed -- is refused as :class:`LatentConditionDuplicate`: it is in force, and a
    second one is not a second risk. A withdrawn one does not count; the same watch
    can be declared again once the first is withdrawn.
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
    # Before the probe: a duplicate of a watch that fired would otherwise be told it
    # "already holds", which is true and not the reason it is refused.
    existing = LatentCondition.objects.filter(
        claim=claim,
        kind=kind,
        subject=probe.subject,
        expected=probe.expected,
        state__in=LATENT_LIVE_STATES,
    ).first()
    if existing is not None:
        raise LatentConditionDuplicate(
            f"this claim already has this condition declared ({existing.uuid}, "
            f"{existing.state}); a second identical declaration is not a second risk. "
            "Withdraw that one to declare it again",
            existing,
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
    try:
        # In a savepoint: the same declaration made concurrently loses on the
        # constraint, and the refusal must not take the caller's transaction with it.
        with transaction.atomic():
            probe.save()
    except IntegrityError as exc:
        raise LatentConditionDuplicate(
            "this claim already has this condition declared -- it was declared a moment "
            "ago; a second identical declaration is not a second risk"
        ) from exc
    return probe


def withdraw_condition(
    condition: LatentCondition, *, note: str = "", withdrawn_by=None, now=None
) -> LatentCondition:
    """Stop watching, visibly. The row is kept, not deleted, so the record shows
    that somebody decided to stop -- a watch that vanishes leaves no trace that it
    ever existed, which is how a gap becomes invisible.

    Who withdrew it, when and why are recorded on their own fields. A FIRED
    condition can be withdrawn too: that is a person accepting the state it fired
    on, and it releases the hold the condition had on its claim, so the retest it
    opened is resolved the ordinary way -- by the next re-derivation that reads the
    claim. What was observed when it fired is kept as it was."""
    condition.state = State.WITHDRAWN
    condition.withdrawn_at = now or timezone.now()
    condition.withdrawn_by = withdrawn_by
    condition.withdrawn_note = note
    condition.save(
        update_fields=["state", "withdrawn_at", "withdrawn_by", "withdrawn_note", "updated_at"]
    )
    return condition


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@transaction.atomic
def evaluate_conditions(deployment, *, actor=None, now=None) -> dict:
    """Re-read every live condition on this deployment's current claims.

    A condition that has become true fires: its claim is moved away from a pass to
    STALE and a retest obligation opens whose reason NAMES the condition. That is
    the whole point -- an operator reading the obligation learns which declared
    precondition gave way, not that some fingerprint moved.

    Every live state is read, not only PENDING:

    - **UNOBSERVABLE** (and **EVALUATION_FAILED**) is read again. A subject back in
      sight returns the condition to PENDING if it does not hold, and fires it if
      it does. Read once and never again, a watch that lost sight of its subject for
      one write -- a provider renamed and renamed back -- was disarmed for good, and
      the change it was declared for went by unseen.
    - **FIRED** is read again. While it holds, its claim stays at STALE with a
      retest open; a claim something moved back to a pass is marked again. Back at
      its baseline, it re-arms to PENDING and resolves the retest it opened. A
      subject it can no longer see does not clear it: that is not the subject coming
      back to its baseline, so the hold stands, and is put back the same way.

    A condition whose subject can no longer be read goes UNOBSERVABLE and is
    counted as a coverage loss. It is never treated as "still does not hold".

    Each condition is read in its OWN savepoint. It was one atomic block, so one
    observer that raised rolled back every other condition's evaluation with it --
    the one that had fired included -- every time. Now the one that raised is
    recorded as EVALUATION_FAILED (a FIRED one keeps its state and its hold), with
    ``last_error_at`` and the TYPE of what was raised, never its text, and every
    other condition is evaluated as if it had not.

    Only CURRENT claim versions are considered, and never a human-REVOKED claim:
    a withdrawn claim is not invalidated, and a superseded version is history.
    Idempotent -- a second run neither re-fires nor opens a duplicate obligation,
    and writes nothing the decision reads unless a condition changed state.
    """
    now = now or timezone.now()
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
                deployment=deployment, state__in=LATENT_LIVE_STATES, claim__in=current_pks
            )
            .select_related("claim", "fired_requirement")
            .order_by("pk")
        )
        run = _Evaluation(deployment, conditions, actor=actor, now=now)
        token = _ACCESS_READ.set({})
        try:
            for condition in conditions:
                run.evaluate(condition)
        finally:
            _ACCESS_READ.reset(token)
    return run.result()


def _reason(condition, observation: str) -> str:
    return (
        f"A declared invalidating condition came true: {condition.description} "
        f"({condition.get_kind_display()}; subject {condition.subject!r}"
        f"{f'; expected {condition.expected!r}' if condition.expected else ''}). "
        f"Observed: {observation}. Declared baseline was: "
        f"{condition.baseline_observation or '(none recorded)'}."
    )


#: What a claim's lifecycle says when a condition that fired on it is found still
#: holding and the claim had been moved back to a pass.
_STILL_HOLDS = (
    "A declared condition that fired on this claim still holds; the claim is held at "
    "stale until the condition re-arms or a person withdraws it."
)


def _still_holding_reason(condition, observation: str = "", *, unread: str = "", restored: bool = False) -> str:
    """The reason a retest re-opened for a FIRED condition gives: read still true,
    no longer readable, or -- ``restored`` -- put back without reading it again."""
    if unread:
        return (
            f"{_reason(condition, condition.fired_observation or '(not recorded)')} It can no "
            f"longer be read ({unread}), which is not the subject back at its baseline: the "
            "hold stands."
        )
    if restored:
        return (
            f"{_reason(condition, condition.fired_observation or '(not recorded)')} It has not "
            "re-armed and nobody withdrew it, so the hold it keeps on its claim is put back."
        )
    return f"{_reason(condition, observation)} It still holds."


def _put_back_hold(deployment, claim, *, reason: str, now, actor, system_fp):
    """The hold a FIRED condition keeps on ``claim``: no better than STALE, and a
    retest open for its identity. Each is put back if something moved it; the retest
    opened, if one was, is returned. ``system_fp`` is called only when one is."""
    from .invalidation import _has_open_requirement, _mark_stale, _open_requirement

    requirement = None
    if not _has_open_requirement(deployment, claim):
        requirement = _open_requirement(
            deployment, claim, system_fp=system_fp(), now=now, actor=actor, reason=reason
        )
    _mark_stale(claim, now, note=_STILL_HOLDS)
    return requirement


class _Evaluation:
    """One evaluation of a deployment's live conditions: what the conditions in it
    share, and what it found."""

    def __init__(self, deployment, conditions, *, actor, now):
        self.deployment = deployment
        self.actor = actor
        self.now = now
        self._system_fp = None
        # One instance per claim, shared by every condition declared on it. Each
        # condition held its own, so two that fired on one claim in one evaluation
        # each found it SUPPORTED and each wrote "supported -> stale". Now the second
        # finds it STALE and writes nothing: one mark, one event.
        self._claims: dict = {}
        self._conditions = {c.pk: c for c in conditions}
        self.found: dict[str, list[str]] = {
            "fired": [], "lost": [], "still_pending": [], "rearmed": [], "still_fired": [], "failed": [],
        }

    # -- shared reads ---------------------------------------------------------

    def system_fp(self) -> str:
        # Only a firing needs it, so a run that fires nothing does not compute it.
        if self._system_fp is None:
            from .fingerprint import compute_system_fingerprint

            self._system_fp = compute_system_fingerprint(self.deployment)
        return self._system_fp

    def claim_of(self, condition) -> AssuranceClaim:
        return self._claims.setdefault(condition.claim_id, condition.claim)

    # -- one condition ---------------------------------------------------------

    def evaluate(self, condition) -> None:
        prior = condition.state
        try:
            with transaction.atomic():
                self._evaluate(condition, prior)
        except Exception as exc:  # recorded on the condition, never raised
            logger.exception(
                "latent condition %s on deployment %s could not be evaluated; it is "
                "recorded as not watched and every other condition is evaluated as usual",
                condition.pk,
                self.deployment.pk,
            )
            self._record_failure(condition, prior, exc)

    def _evaluate(self, condition, prior) -> None:
        uid = str(condition.uuid)
        try:
            holds, observation = observe(condition, self.deployment)
        except Unobservable as exc:
            if prior == State.FIRED:
                # Out of sight is not back at baseline. The hold stands -- and is put
                # back where something removed it, as for a condition read still true;
                # what was observed when it fired is left as it was.
                self._hold(condition, unread=str(exc))
                self.found["still_fired"].append(uid)
                return
            self._save(condition, state=State.UNOBSERVABLE, fired_observation=str(exc))
            self.found["lost"].append(uid)
            return
        if prior == State.FIRED:
            if holds:
                self._hold(condition, observation)
                self.found["still_fired"].append(uid)
            else:
                self._rearm(condition, observation)
                self.found["rearmed"].append(uid)
            return
        if holds:
            self._fire(condition, observation)
            self.found["fired"].append(uid)
            return
        # Not true. From PENDING that is "still pending"; from UNOBSERVABLE or a
        # failed evaluation it is the subject back in sight, at its baseline -- and
        # the note of why it could not be read no longer describes it.
        back = {"fired_observation": ""} if prior == State.UNOBSERVABLE else {}
        self._save(condition, state=State.PENDING, **back)
        self.found["still_pending"].append(uid)

    def _fire(self, condition, observation: str) -> None:
        from .invalidation import _has_open_requirement, _mark_stale, _open_requirement

        claim = self.claim_of(condition)
        requirement = None
        if not _has_open_requirement(self.deployment, claim):
            requirement = _open_requirement(
                self.deployment,
                claim,
                system_fp=self.system_fp(),
                now=self.now,
                actor=self.actor,
                reason=_reason(condition, observation),
            )
        _mark_stale(claim, self.now)
        self._save(
            condition,
            state=State.FIRED,
            fired_at=self.now,
            fired_observation=observation,
            fired_requirement=requirement,
        )

    def _hold(self, condition, observation: str = "", *, unread: str = "") -> None:
        """A FIRED condition that still holds, or that can no longer be read: its
        claim reads no better than STALE and a retest is open. Both are already so,
        unless something moved them -- a person moved the claim back to a pass, or a
        re-derive resolved the retest before a fired condition held one -- and each is
        put back if it was. ``unread``: why the subject cannot be read now, for a
        condition out of sight, which is not back at its baseline."""
        requirement = _put_back_hold(
            self.deployment,
            self.claim_of(condition),
            reason=_still_holding_reason(condition, observation, unread=unread),
            now=self.now,
            actor=self.actor,
            system_fp=self.system_fp,
        )
        self._save(condition, **({} if requirement is None else {"fired_requirement": requirement}))

    def _rearm(self, condition, observation: str) -> None:
        """A FIRED condition found back at its baseline: watched again, and the
        retest it opened is resolved -- unless another condition that fired on the
        same claim still holds it, which then answers for that retest."""
        claim = self.claim_of(condition)
        requirement = condition.fired_requirement
        if requirement is not None and requirement.resolved_at is None:
            others = list(
                LatentCondition.objects.filter(
                    deployment=self.deployment,
                    claim__fingerprint=claim.fingerprint,
                    state=State.FIRED,
                )
                .exclude(pk=condition.pk)
                .values_list("pk", "fired_requirement_id")
                .order_by("pk")
            )
            if others:
                unowned = [pk for pk, owned in others if owned is None]
                if unowned:
                    LatentCondition.objects.filter(pk=unowned[0]).update(fired_requirement=requirement)
                    if unowned[0] in self._conditions:
                        self._conditions[unowned[0]].fired_requirement = requirement
            else:
                requirement.resolved_at = self.now
                requirement.resolving_claim = claim
                requirement.save(update_fields=["resolved_at", "resolving_claim", "updated_at"])
                ClaimEvent.objects.create(
                    claim=claim,
                    from_status=claim.status,
                    to_status=claim.status,
                    actor=None,
                    note=(
                        "Retest requirement resolved: the declared condition that opened it "
                        f"no longer holds ({observation}); it is watched again."
                    ),
                )
        fired = condition.fired_observation
        self._save(
            condition,
            state=State.PENDING,
            fired_observation=(
                f"Re-armed: {observation}. It had fired"
                f"{f' at {condition.fired_at.isoformat()}' if condition.fired_at else ''}"
                f"{f' on: {fired}' if fired else ''}."
            ),
        )

    def _save(self, condition, **changes) -> None:
        """Write what this evaluation found. ``state`` is written only when it moved:
        it is the column the decision reads, and an evaluation that changed nothing
        must not schedule a refresh that evaluates again."""
        fields = ["last_evaluated_at", "updated_at"]
        condition.last_evaluated_at = self.now
        if condition.last_error_at is not None or condition.last_error:
            condition.last_error_at = None
            condition.last_error = ""
            fields += ["last_error_at", "last_error"]
        for name, value in changes.items():
            if name == "fired_requirement":
                if condition.fired_requirement_id == (None if value is None else value.pk):
                    continue
            elif getattr(condition, name) == value:
                continue
            setattr(condition, name, value)
            fields.append(name)
        condition.save(update_fields=fields)

    def _record_failure(self, condition, prior, exc) -> None:
        """Record on the condition that its evaluation failed, in its own savepoint.

        A FIRED one keeps its state: a failure to read it is not the subject coming
        back to its baseline, so the hold stands. Any other goes EVALUATION_FAILED,
        which the posture counts as not watching and the decision reads as a
        precondition nobody can check. The type of what was raised is kept, never
        its text -- an exception's message can carry what it read. If even this
        write fails, it is logged and the evaluation goes on.
        """
        self.found["failed"].append(str(condition.uuid))
        # What the rolled-back savepoint left in memory is not what is stored: the
        # claim is read again before another condition on it uses it.
        self._claims.pop(condition.claim_id, None)
        try:
            with transaction.atomic():
                self._claims[condition.claim_id] = AssuranceClaim.objects.get(pk=condition.claim_id)
                condition.refresh_from_db()
                fields = ["last_error_at", "last_error", "updated_at"]
                condition.last_error_at = self.now
                condition.last_error = f"the evaluator raised {type(exc).__name__}"[:200]
                if prior != State.FIRED and condition.state != State.EVALUATION_FAILED:
                    condition.state = State.EVALUATION_FAILED
                    fields.append("state")
                condition.save(update_fields=fields)
        except (DatabaseError, LatentCondition.DoesNotExist, AssuranceClaim.DoesNotExist):
            logger.exception(
                "the failed evaluation of latent condition %s could not be recorded on it",
                condition.pk,
            )

    def result(self) -> dict:
        return _result(self.deployment, self.now, **self.found)


def _result(deployment, now, *, fired, lost, still_pending, rearmed=(), still_fired=(), failed=()) -> dict:
    return {
        "deployment": str(deployment.uuid),
        "evaluated_at": now.isoformat(),
        "fired": list(fired),
        "fired_count": len(fired),
        # Counted and named separately from "pending". A condition we can no
        # longer read is not one that has not happened.
        "unobservable": list(lost),
        "unobservable_count": len(lost),
        "still_pending": list(still_pending),
        "still_pending_count": len(still_pending),
        # A fired condition found back at its baseline, watched again.
        "rearmed": list(rearmed),
        "rearmed_count": len(rearmed),
        # A fired condition still holding its claim at stale.
        "still_fired": list(still_fired),
        "still_fired_count": len(still_fired),
        # The evaluator raised on these; they are not watched until it does not.
        "evaluation_failed": list(failed),
        "evaluation_failed_count": len(failed),
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

    Numbers, never blended. Pending is not a safety measure, fired is work already
    owed, unobservable is watch we have lost, and a failed evaluation is watch we
    could not run -- each calls for something different, and one percentage would
    hide the last two.
    """
    conditions = list(
        LatentCondition.objects.filter(deployment=deployment).select_related("claim", "withdrawn_by")
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
        # And this one for the same reason: a condition the evaluator raised on is
        # not watched, however recently it was declared.
        "evaluation_failed": by_state.get(State.EVALUATION_FAILED, 0),
        "unwatched": len(unwatched),
        "conditions": [condition_view(c) for c in conditions],
        "note": (
            "Watching counts named preconditions that have not happened as of each "
            "one's last evaluation. It is not a prediction and not an all-clear. "
            "coverage_lost counts conditions whose subject can no longer be read: "
            "those are unwatched, not safe. So are the ones counted as "
            "evaluation_failed, whose last evaluation raised, and the ones counted as "
            "unwatched, declared on a claim nothing evaluates any more (a closed "
            "version, or one a person revoked). A fired condition holds its claim at "
            "stale until it is found back at its baseline or a person withdraws it."
        ),
    }


def _evaluated_claim(claim) -> bool:
    """Whether :func:`evaluate_conditions` reads conditions declared on ``claim``."""
    return claim.valid_to is None and claim.status != AssuranceClaim.ClaimStatus.REVOKED


def _iso(moment):
    return moment.isoformat() if moment else None


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
        "fired_at": _iso(c.fired_at),
        "last_evaluated_at": _iso(c.last_evaluated_at),
        "last_error_at": _iso(c.last_error_at),
        "last_error": c.last_error,
        "withdrawn_at": _iso(c.withdrawn_at),
        "withdrawn_by": c.withdrawn_by.username if c.withdrawn_by_id else None,
        "withdrawn_note": c.withdrawn_note,
    }


# ---------------------------------------------------------------------------
# In production: when a write could make a declared condition true
# ---------------------------------------------------------------------------


def fire_due_conditions(deployment, *, actor=None, now=None) -> int:
    """Evaluate ``deployment``'s live conditions now; the number that fired.

    Called wherever the deployment's stored decision is brought current AFTER a
    write commits -- the backstop in :mod:`assurance.signals`, which every route
    that refreshes the decision schedules -- and inline only on the few writes that
    are not a stop: a data boundary write for its own deployment, the invalidation
    check, a scan ingest (itself run after the scan's completion committed).
    Never inside a revoke, a pause or any other stop: see the module docstring.

    A condition firing marks its claim STALE and opens a retest, and the decision
    is refreshed after this, so it reads them. Never raises: it runs where a failure
    must not undo what went before it. A condition whose own evaluation fails is
    recorded as failed and the rest are evaluated (:func:`evaluate_conditions`); if
    the evaluation cannot run at all, that is logged, and every live condition on a
    current claim is recorded as not evaluated, best effort, so the posture and the
    decision do not go on reading it as watched. Returns 0 at once, with one query,
    for a deployment with no live condition.
    """
    now = now or timezone.now()
    try:
        if not LatentCondition.objects.filter(
            deployment=deployment, state__in=LATENT_LIVE_STATES
        ).exists():
            return 0
        with transaction.atomic():
            return evaluate_conditions(deployment, actor=actor, now=now)["fired_count"]
    except Exception as exc:  # never raised into the write it follows
        logger.exception(
            "latent conditions on deployment %s were not evaluated; each is recorded "
            "as not evaluated and keeps the last_evaluated_at of the last evaluation "
            "that completed",
            deployment.pk,
        )
        _record_not_evaluated(deployment, now, exc)
        return 0


def _record_not_evaluated(deployment, now, exc) -> None:
    """Best effort, in a savepoint: every live condition on a current claim of
    ``deployment`` did not get evaluated. A FIRED one keeps its state and its hold."""
    error = f"the evaluator raised {type(exc).__name__}"[:200]
    try:
        with transaction.atomic():
            current = (
                AssuranceClaim.objects.filter(deployment=deployment)
                .current()
                .exclude(status=AssuranceClaim.ClaimStatus.REVOKED)
                .values("pk")
            )
            live = LatentCondition.objects.filter(
                deployment=deployment, state__in=LATENT_LIVE_STATES, claim__in=current
            )
            live.filter(state=State.FIRED).update(last_error_at=now, last_error=error, updated_at=now)
            live.exclude(state=State.FIRED).update(
                state=State.EVALUATION_FAILED, last_error_at=now, last_error=error, updated_at=now
            )
    except DatabaseError:
        logger.exception(
            "the failed evaluation of deployment %s's latent conditions could not be recorded",
            deployment.pk,
        )


def _lifted_holds(deployment_id=None):
    """Each FIRED condition whose hold on its claim is not in place, with the claim
    version it holds -- the current, unrevoked version of the claim it fired on, which
    reads better than STALE or has no retest open for its identity. Only the
    deployment ``deployment_id``, when one is named. Reads, and writes nothing."""
    from .invalidation import _STALE_SKIP

    fired = LatentCondition.objects.filter(state__in=LATENT_HOLDING_STATES).select_related("claim")
    if deployment_id is not None:
        fired = fired.filter(deployment_id=deployment_id)
    lifted = []
    for condition in fired.order_by("deployment_id", "pk"):
        claim = (
            AssuranceClaim.objects.filter(
                deployment_id=condition.deployment_id, fingerprint=condition.claim.fingerprint
            )
            .current()
            .exclude(status=AssuranceClaim.ClaimStatus.REVOKED)
            .first()
        )
        if claim is None:
            continue
        retest_open = RetestRequirement.objects.filter(
            deployment_id=condition.deployment_id,
            claim__fingerprint=claim.fingerprint,
            resolved_at__isnull=True,
        ).exists()
        if claim.status not in _STALE_SKIP or not retest_open:
            lifted.append((condition, claim))
    return lifted


def deployments_with_a_lifted_hold() -> list:
    """The deployments where a FIRED condition's hold on its claim is not in place
    (:func:`restore_fired_holds`), by pk, in order."""
    return sorted({condition.deployment_id for condition, _claim in _lifted_holds()})


@transaction.atomic
def restore_fired_holds(deployment, *, now=None) -> int:
    """Put back the hold each FIRED condition on ``deployment`` keeps on its claim,
    wherever something removed it; the number of conditions whose hold was put back.

    Without reading any condition again: a FIRED condition holds its claim until an
    evaluation finds it back at its baseline or a person withdraws it, and until then
    the hold is a fact of the record, not of a reading. It is what the evaluation's
    own hold does (:class:`_Evaluation`), for the case nothing evaluates: the upgrade
    from a release whose re-derive read a held claim back to a pass and resolved its
    retest while the condition stayed FIRED. The claim held is the current, unrevoked
    version of the one the condition fired on -- a condition left on an older version
    holds the claim, not that version.

    Writes a claim and a retest, which the backstop refreshes the decision after, as
    any other writer's. Never inside a stop: called from the upgrade only.
    """
    now = now or timezone.now()
    system_fp = []

    def fingerprint():
        if not system_fp:
            from .fingerprint import compute_system_fingerprint

            system_fp.append(compute_system_fingerprint(deployment))
        return system_fp[0]

    restored = 0
    # One instance per claim, as in an evaluation: two conditions holding one claim
    # mark it once, and write one event.
    claims: dict = {}
    for condition, claim in _lifted_holds(deployment.pk):
        claim = claims.setdefault(claim.pk, claim)
        requirement = _put_back_hold(
            deployment,
            claim,
            reason=_still_holding_reason(condition, restored=True),
            now=now,
            actor=None,
            system_fp=fingerprint,
        )
        if requirement is not None and condition.claim_id == claim.pk:
            LatentCondition.objects.filter(pk=condition.pk).update(fired_requirement=requirement, updated_at=now)
        restored += 1
    return restored


def deployments_watching_boundary(deployment_id) -> set:
    """``{deployment_id}`` if a live condition there reads its data boundary --
    pending, fired, or one that could not be read, all of which are read again."""
    watched = LatentCondition.objects.filter(
        deployment_id=deployment_id, state__in=LATENT_LIVE_STATES, kind__in=BOUNDARY_KINDS
    ).exists()
    return {deployment_id} if watched else set()


def deployments_watching_provider(*names) -> set:
    """The deployments where a live condition reads the profile of a provider
    called any of ``names`` -- every name the write touched, the one it had before
    a rename included, since a condition naming that one now names nothing, and the
    one it has after, since a condition that lost sight of it can now read it again."""
    wanted = {str(n) for n in names if n}
    if not wanted:
        return set()
    return set(
        LatentCondition.objects.filter(
            state__in=LATENT_LIVE_STATES, kind=Kind.PROVIDER_POSTURE_CHANGES, subject__in=wanted
        ).values_list("deployment_id", flat=True)
    )
