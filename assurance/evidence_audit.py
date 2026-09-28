"""The SPINE verdict / evidence audit (issue #333): what recorded evidence may do to a claim.

A claim's ``status`` is the deriver's reading of the stored graph, or a person's
attributed judgment (:mod:`assurance.claims`). Evidence objects recorded against a
claim (:class:`~assurance.models.ClaimEvidence`) are a second input, and this
module decides what each one is allowed to do. The rule it exists to keep:

**Evidence that is target-authored, stale, contradictory, about another subject,
or warranted only by a signature can never upgrade a claim.** It is recorded,
with the reason it carries no weight, and the only direction it can ever push a
claim is away from a pass.

What carries weight (:func:`classify`)
--------------------------------------
An item is load-bearing only when every one of these holds; each failure is a
named reason, and an item can carry several:

- its origin is an observer INDEPENDENT of the system under assurance. The
  target's own report of itself is ``target_authored``; an operator's, a vendor's
  or an unknown party's is ``not_independent``;
- it is live: not past its expiry, not invalidated by a person, not superseded by
  a successor that itself carries weight, observed at a stated instant that is not
  in the future;
- it names THIS claim: this deployment, this claim type, this component (or no
  component, for a deployment-wide claim), the served route serving now, and the
  input fingerprint of the version being audited;
- an INDEPENDENT STATE CHECK backs what it asserts. A verified signature says who
  produced the bytes and that they are unaltered; it says nothing about whether
  the observation in them was true or complete. An item whose only warrant is its
  signature -- or whose "state check" is its own content digest -- asserts an
  effect nobody checked, and is ``no_independent_state_check``.

What the answer is (:func:`audit`)
----------------------------------
The claim's reading (its status before this audit held it) and the load-bearing
items are read together:

- load-bearing evidence on BOTH sides is CONTESTED -- never resolved to the
  favourable reading, and the contradiction is recorded;
- only fail is FAIL; only pass is PASS -- unless adverse evidence was refused or
  an item says itself it is partial, which is INCOMPLETE;
- nothing on either side is INCOMPLETE when adverse evidence was refused, or an
  independent observer's evidence about the claim was refused as stale or
  unchecked, and INSUFFICIENT_EVIDENCE otherwise -- evidence from a party that can
  never carry weight is no evidence. That last answer is terminal and first-class:
  it is stored as itself (:class:`~assurance.models.ClaimVerdict`), never coerced
  to pass or fail.

What the answer does to the claim
---------------------------------
It can only ever hold a claim BACK, never lift it past its own reading:

- FAIL on load-bearing evidence moves the claim to CONTRADICTED;
- CONTESTED, or INCOMPLETE because adverse evidence was refused or is partial,
  holds it at UNKNOWN (``confidence`` None);
- PASS and INSUFFICIENT_EVIDENCE move nothing. A PASS is the evidence agreeing
  with the claim; it is not a promotion. Upward moves stay where they were: the
  deriver's reading of the graph, and an attributed human transition -- which is
  now refused where this audit would hold the target status back
  (:func:`assurance.claims.apply_claim_transition`).

Refused ADVERSE evidence still weighs toward incomplete (fail-closed): a stale
contradiction, or a target that reports its own failure, is not proof of failure
and is not dismissed either. Evidence that names another deployment, claim or
component, or that a person invalidated with a reason, weighs nothing.

Who may record, and what origin means
-------------------------------------
``origin``, ``signer`` and ``signature_verified`` are facts about the CHANNEL an
item arrived on, so they are set by the server code that received it --
:func:`record_claim_evidence` has no API route, and the claim's evidence read is
GET-only. A future ingest path must take them from the channel (a keyring-verified
engine envelope, say), never from the payload: a record that may declare itself
independent is a target that may declare itself independent.

Attribution (:func:`attribution`) keeps account, device, organisation and person
apart, and never reads a signature or a service account's action as a person's
intent: ``personal_intent`` is always ``not_established``, because nothing in an
evidence record can establish it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .change import EVIDENCE_TTL_DAYS
from .models import AssuranceClaim, ClaimEvent, ClaimEvidence, ClaimVerdict, EvidenceClass

Status = AssuranceClaim.ClaimStatus
Origin = ClaimEvidence.Origin

#: The literal an area carries when nothing recorded it. Present, never absent.
UNKNOWN = "unknown"

#: The ten record areas every evidence object binds (issue #333, guide section 12.3).
RECORD_AREAS = (
    "identity",
    "authority",
    "inputs",
    "action",
    "execution",
    "observation",
    "finding",
    "responsibility",
    "repair",
    "claim",
)
#: The areas a caller supplies as-is; the other six are read off the row's columns.
CARRIED_AREAS = frozenset({"action", "execution", "finding", "repair"})

#: How far in the future an observation's instant may be before it is refused.
MAX_CLOCK_SKEW = timedelta(minutes=5)

# ---------------------------------------------------------------------------
# Why an item carries no weight. Each is a fact about the item, not a score.
# ---------------------------------------------------------------------------

TARGET_AUTHORED = "target_authored"
NOT_INDEPENDENT = "not_independent"
EXPIRED = "expired"
INVALIDATED = "invalidated"
SUPERSEDED = "superseded"
NO_OBSERVATION_INSTANT = "no_observation_instant"
OBSERVED_IN_THE_FUTURE = "observed_in_the_future"
NAMES_NO_SUBJECT = "names_no_subject"
NAMES_ANOTHER_DEPLOYMENT = "names_another_deployment"
NAMES_ANOTHER_CLAIM = "names_another_claim"
NAMES_ANOTHER_COMPONENT = "names_another_component"
NAMES_ANOTHER_SERVED_ROUTE = "names_another_served_route"
NAMES_NO_SERVED_ROUTE = "names_no_served_route"
TAKEN_AGAINST_OTHER_INPUTS = "taken_against_other_inputs"
NAMES_NO_INPUTS = "names_no_inputs"
NO_INDEPENDENT_STATE_CHECK = "no_independent_state_check"
STATE_CHECK_IS_THE_RECORD = "state_check_is_the_record_itself"
UNGRADED = "ungraded"

#: Reasons under which an item is not about this claim at all, or was retired by a
#: person or a load-bearing successor: it weighs nothing, in either direction.
NEUTRAL_REASONS = frozenset(
    {
        INVALIDATED,
        SUPERSEDED,
        NAMES_NO_SUBJECT,
        NAMES_ANOTHER_DEPLOYMENT,
        NAMES_ANOTHER_CLAIM,
        NAMES_ANOTHER_COMPONENT,
    }
)

#: Reasons about WHO produced an item: it could never carry weight, however fresh,
#: well-aimed or checked it is.
ORIGIN_REASONS = frozenset({TARGET_AUTHORED, NOT_INDEPENDENT})

#: Evidence classes that grade nothing: an item asserting pass or fail at one of
#: these has not said how it knows.
_UNGRADED_CLASSES = frozenset({EvidenceClass.UNKNOWN.value, EvidenceClass.NOT_DOCUMENTED.value})
#: The grades that are an observation (Observed, in the qualitative vocabulary): the
#: only grades under which a claim's own reading counts as the pass side.
_OBSERVED_CLASSES = frozenset(
    {EvidenceClass.TECHNICALLY_VERIFIED.value, EvidenceClass.CONFIGURATION_VERIFIED.value}
)
#: The outcomes an item may carry. CONTESTED is an answer about a SET of evidence;
#: one item cannot contest itself.
ITEM_OUTCOMES = frozenset(
    {
        ClaimVerdict.PASS.value,
        ClaimVerdict.FAIL.value,
        ClaimVerdict.INCOMPLETE.value,
        ClaimVerdict.INSUFFICIENT_EVIDENCE.value,
    }
)
#: The outcomes that bear against a claim.
_ADVERSE = frozenset({ClaimVerdict.FAIL.value, ClaimVerdict.INCOMPLETE.value})

#: The statuses the audit never reads or moves: a withdrawal and closed history.
_UNAUDITED_STATUSES = frozenset({Status.REVOKED.value, Status.SUPERSEDED.value})
#: Readiness order, weakest first, for "never move a claim up".
_RANK = {
    Status.CONTRADICTED.value: 0,
    Status.UNKNOWN.value: 1,
    Status.STALE.value: 1,
    Status.DRAFT.value: 1,
    Status.SUPPORTED.value: 2,
    Status.PARTIALLY_VERIFIED.value: 2,
    Status.VERIFIED.value: 3,
}

#: What a signature is, said once, wherever an item was refused for resting on one.
SIGNATURE_IS_NOT_TRUTH = (
    "A verified signature shows who produced a record and that it is unaltered; it is "
    "not evidence that the observation in it was true or complete."
)


class EvidenceRefused(ValueError):
    """A record the audit cannot even hold -- a malformed or self-contradicting
    evidence object. A caller turns this into a clean 400."""


@dataclass(frozen=True)
class Subject:
    """What an audited claim version is about: the values an item must name."""

    deployment: str
    claim_type: str
    asset: str
    inputs: str
    route: str


def rank(status: str) -> int:
    """A status's place in readiness order (0 weakest). Unknown values rank as
    UNKNOWN, never as a pass."""
    return _RANK.get(str(status), 1)


def subject_of(claim: AssuranceClaim, *, route: str, inputs: str | None = None) -> Subject:
    """The :class:`Subject` of a stored claim version. ``inputs`` defaults to the
    fingerprint the version is bound to -- its own input fingerprint, or for a row
    bound before those existed, its system fingerprint."""
    return Subject(
        deployment=str(claim.deployment.uuid),
        claim_type=str(claim.claim_type),
        asset=str(claim.asset.uuid) if claim.asset_id else "",
        inputs=inputs if inputs is not None else (claim.input_fingerprint or claim.system_fingerprint),
        route=route,
    )


# ---------------------------------------------------------------------------
# Classification -- one item against one claim version
# ---------------------------------------------------------------------------


def _intrinsic_reasons(item: ClaimEvidence, subject: Subject, now) -> list[str]:
    """Every reason ``item`` carries no weight, leaving supersession aside."""
    reasons: list[str] = []

    # Authority: who produced it.
    if item.origin == Origin.TARGET:
        reasons.append(TARGET_AUTHORED)
    elif item.origin != Origin.INDEPENDENT:
        reasons.append(NOT_INDEPENDENT)

    # Liveness.
    if item.invalidated_at is not None and item.invalidated_at <= now:
        reasons.append(INVALIDATED)
    if item.expires_at is None or item.expires_at <= now:
        reasons.append(EXPIRED)
    if item.observed_at is None:
        reasons.append(NO_OBSERVATION_INSTANT)
    elif item.observed_at > now + MAX_CLOCK_SKEW:
        reasons.append(OBSERVED_IN_THE_FUTURE)

    # Identity: what it names. Blank never matches -- an item that names no subject
    # is not about this one (the #235 lineage: naming nothing scores as invention).
    if not item.subject_deployment or not item.subject_claim_type:
        reasons.append(NAMES_NO_SUBJECT)
    else:
        if item.subject_deployment != subject.deployment:
            reasons.append(NAMES_ANOTHER_DEPLOYMENT)
        if item.subject_claim_type != subject.claim_type:
            reasons.append(NAMES_ANOTHER_CLAIM)
    if (item.subject_asset or "") != subject.asset:
        # Evidence about one component does not establish a deployment-wide claim,
        # and evidence about the deployment does not establish one component's.
        reasons.append(NAMES_ANOTHER_COMPONENT)
    if not item.subject_route:
        reasons.append(NAMES_NO_SERVED_ROUTE)
    elif item.subject_route != subject.route:
        reasons.append(NAMES_ANOTHER_SERVED_ROUTE)
    if not item.subject_inputs or not subject.inputs:
        reasons.append(NAMES_NO_INPUTS)
    elif item.subject_inputs != subject.inputs:
        reasons.append(TAKEN_AGAINST_OTHER_INPUTS)

    # Observation: an asserted effect needs an independent check of the state, and
    # a grade that says how it is known. Integrity is not that check.
    if item.outcome in (ClaimVerdict.PASS.value, ClaimVerdict.FAIL.value):
        check = (item.state_check_ref or "").strip()
        if not check or item.state_checked_at is None:
            reasons.append(NO_INDEPENDENT_STATE_CHECK)
        elif check in {
            (item.content_digest or "").strip(),
            (item.signer or "").strip(),
        } - {""}:
            reasons.append(STATE_CHECK_IS_THE_RECORD)
        if item.evidence_class in _UNGRADED_CLASSES:
            reasons.append(UNGRADED)
    return reasons


def classify(items, subject: Subject, now) -> dict[int, list[str]]:
    """``{item.pk: reasons}`` for every item; an empty list means load-bearing.

    Supersession is decided here, across the set: an item is retired by its
    successor only when the successor itself carries weight. A successor the
    target wrote, or one that is stale, cannot retire an independent observation
    -- or a target could make a contradiction disappear by filing over it."""
    items = list(items)
    intrinsic = {item.pk: _intrinsic_reasons(item, subject, now) for item in items}
    by_pk = {item.pk: item for item in items}

    def carries_weight(pk, seen=()) -> bool:
        item = by_pk.get(pk)
        if item is None or pk in seen or intrinsic[pk]:
            return False
        successor = item.superseded_by_id
        return successor is None or not carries_weight(successor, seen + (pk,))

    out: dict[int, list[str]] = {}
    for item in items:
        reasons = list(intrinsic[item.pk])
        successor = item.superseded_by_id
        if successor is not None and carries_weight(successor, (item.pk,)):
            reasons.append(SUPERSEDED)
        out[item.pk] = reasons
    return out


# ---------------------------------------------------------------------------
# The audit -- a set of items against a claim's reading
# ---------------------------------------------------------------------------


def _base_side(base_status: str, *, vendor_asserted: bool, evidence_class: str) -> str:
    """Which side the claim's own reading stands on: ``pass`` only for a pass the
    platform itself observed (not a vendor's word, not an inference), ``fail`` for a
    contradicted claim, ``stale`` for an expired one, otherwise nothing."""
    if base_status == Status.CONTRADICTED:
        return "fail"
    if base_status == Status.STALE:
        return "stale"
    if (
        base_status in (Status.SUPPORTED, Status.VERIFIED)
        and not vendor_asserted
        and evidence_class in _OBSERVED_CLASSES
    ):
        return "pass"
    return ""


def audit(
    *,
    base_status: str,
    vendor_asserted: bool,
    evidence_class: str,
    subject: Subject,
    items,
    now,
) -> dict | None:
    """The evidence audit of one claim version, or ``None`` when no evidence was
    recorded against it (nothing to audit: the status is the reading's own).

    Pure: reads nothing and writes nothing. Returns the stored form
    (:attr:`AssuranceClaim.evidence_audit`): the verdict, the status the claim is
    held at (never above ``base_status``), what carried weight, what was refused
    and why, the contradictions and the residual uncertainty."""
    items = list(items)
    if not items or str(base_status) in _UNAUDITED_STATUSES:
        return None
    reasons = classify(items, subject, now)

    admitted = [i for i in items if not reasons[i.pk]]
    refused = [i for i in items if reasons[i.pk]]
    passes = [i for i in admitted if i.outcome == ClaimVerdict.PASS]
    fails = [i for i in admitted if i.outcome == ClaimVerdict.FAIL]
    partial = [i for i in admitted if i.outcome == ClaimVerdict.INCOMPLETE]
    # Refused evidence that bears against the claim, about this claim, not retired:
    # not proof of failure, and not dismissed either.
    degrading = [
        i for i in refused
        if i.outcome in _ADVERSE and not (set(reasons[i.pk]) & NEUTRAL_REASONS)
    ]
    # Anything else an independent observer recorded about this claim that could
    # not be used -- stale or unchecked corroboration among it: it cannot prop a
    # claim up, and it keeps "we cannot say" from reading as though nothing had been
    # looked at. An item from a party that could never carry weight (the target, an
    # operator, a vendor) is not "incomplete" evidence: it is no evidence.
    unusable = [
        i for i in refused
        if not (set(reasons[i.pk]) & (NEUTRAL_REASONS | ORIGIN_REASONS))
    ]

    side = _base_side(str(base_status), vendor_asserted=vendor_asserted, evidence_class=evidence_class)
    pass_side = side == "pass" or bool(passes)
    fail_side = side == "fail" or bool(fails)

    contradictions: list[str] = []
    if pass_side and fail_side:
        verdict = ClaimVerdict.CONTESTED
        for_ = [f"evidence {i.uuid}" for i in passes] + (["the claim's own reading"] if side == "pass" else [])
        against = [f"evidence {i.uuid}" for i in fails] + (["the claim's own reading"] if side == "fail" else [])
        contradictions.append(
            "Load-bearing evidence disagrees: " + ", ".join(for_) + " reads pass; "
            + ", ".join(against) + " reads fail. Not resolved to either reading."
        )
    elif fail_side:
        verdict = ClaimVerdict.FAIL
    elif pass_side:
        verdict = ClaimVerdict.INCOMPLETE if (partial or degrading or side == "stale") else ClaimVerdict.PASS
    else:
        verdict = (
            ClaimVerdict.INCOMPLETE
            if (partial or degrading or unusable or side == "stale")
            else ClaimVerdict.INSUFFICIENT_EVIDENCE
        )
    for i in degrading:
        contradictions.append(
            f"Evidence {i.uuid} reads {i.outcome} and carries no weight "
            f"({', '.join(reasons[i.pk])}); the claim cannot pass over it."
        )

    # What the answer does to the claim: hold it back, never lift it.
    target = str(base_status)
    if verdict == ClaimVerdict.FAIL and fails:
        target = Status.CONTRADICTED.value
    elif verdict == ClaimVerdict.CONTESTED or (
        verdict == ClaimVerdict.INCOMPLETE and (partial or degrading)
    ):
        target = Status.UNKNOWN.value
    held = rank(target) < rank(base_status)
    status = target if held else str(base_status)

    residual: list[str] = []
    for i in admitted:
        residual.extend(str(u) for u in (i.residual_uncertainty or []))
    if any(NO_INDEPENDENT_STATE_CHECK in reasons[i.pk] and i.signature_verified for i in refused):
        residual.append(SIGNATURE_IS_NOT_TRUTH)
    if verdict == ClaimVerdict.INSUFFICIENT_EVIDENCE:
        residual.append(
            "No evidence that could carry weight was recorded for this claim; this is "
            "the answer, not a failure and not a pass."
        )

    return {
        "verdict": verdict.value,
        "base_status": str(base_status),
        "status": status,
        "held": held,
        "admitted": [{"uuid": str(i.uuid), "outcome": i.outcome} for i in admitted],
        "refused": [
            {
                "uuid": str(i.uuid),
                "outcome": i.outcome,
                "reasons": reasons[i.pk],
                "weighs": "toward_incomplete" if i in degrading else "nothing",
            }
            for i in refused
        ],
        "contradictions": contradictions,
        "residual_uncertainty": residual,
        "subject": {"route": subject.route, "inputs": subject.inputs},
        "audited_at": now.isoformat(),
    }


def audit_note(result: dict) -> str:
    """The ClaimEvent note for a move the audit made."""
    if result["held"]:
        why = result["contradictions"][0] if result["contradictions"] else ""
        return _clip(f"Evidence audit: {result['verdict']}; held at {result['status']}. {why}")
    return _clip(f"Evidence audit: {result['verdict']}; the hold is released.")


def _clip(text: str, limit: int = 1000) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ---------------------------------------------------------------------------
# Applying the audit to a stored claim
# ---------------------------------------------------------------------------


def evidence_for(claim: AssuranceClaim):
    """The evidence recorded against ``claim``'s identity, oldest first."""
    return ClaimEvidence.objects.filter(
        deployment_id=claim.deployment_id, claim_fingerprint=claim.fingerprint
    ).order_by("created_at", "pk")


def reading_status(claim: AssuranceClaim) -> str:
    """The claim's status before the audit held it back: what the deriver or a
    person put there. Only while the claim still reads exactly what the audit held
    it at: any other writer since -- a STALE mark, a withdrawal, a person -- wrote
    the reading itself."""
    audit = claim.evidence_audit or {}
    if audit.get("held") and claim.status == audit.get("status") and audit.get("base_status"):
        return audit["base_status"]
    return claim.status


def _is_audited(claim: AssuranceClaim) -> bool:
    return claim.valid_to is None and claim.effective_to is None and claim.status not in _UNAUDITED_STATUSES


def audit_of(claim: AssuranceClaim, *, base_status: str | None = None, now=None, route: str | None = None):
    """:func:`audit` of a stored claim version, reading its evidence and the route
    serving now. ``base_status`` defaults to the claim's own reading."""
    from .served_route import serving_route_now

    now = now or timezone.now()
    items = list(evidence_for(claim))
    if not items:
        return None
    route = route if route is not None else serving_route_now(claim.deployment)
    return audit(
        base_status=base_status if base_status is not None else reading_status(claim),
        vendor_asserted=claim.vendor_asserted,
        evidence_class=claim.evidence_class,
        subject=subject_of(claim, route=route),
        items=items,
        now=now,
    )


@transaction.atomic
def audit_claim(claim: AssuranceClaim, *, now=None) -> dict | None:
    """Audit a CURRENT claim version in place and write the answer onto it.

    Holds the claim back (or releases a hold its evidence no longer supports, back
    to its own reading -- never above it), writes ``evidence_verdict`` and
    ``evidence_audit``, and records any status move as a :class:`ClaimEvent` with
    ``cause`` evidence_audit and no actor. Returns the audit, or ``None`` when the
    claim is not current, is withdrawn, or has no evidence recorded against it."""
    from .claims import _confidence

    if not _is_audited(claim):
        return None
    now = now or timezone.now()
    result = audit_of(claim, now=now)
    if result is None:
        return None
    old_status = claim.status
    new_status = result["status"]
    claim.evidence_verdict = result["verdict"]
    claim.evidence_audit = result
    fields = ["evidence_verdict", "evidence_audit", "updated_at"]
    if new_status != old_status:
        claim.status = new_status
        claim.confidence = _confidence(new_status, claim.evidence_class)
        fields += ["status", "confidence"]
    claim.save(update_fields=fields)
    if new_status != old_status:
        ClaimEvent.objects.create(
            claim=claim,
            from_status=old_status,
            to_status=new_status,
            actor=None,
            cause=ClaimEvent.CAUSE_EVIDENCE_AUDIT,
            note=audit_note(result),
        )
    return result


def refusal_for_transition(claim: AssuranceClaim, to_status: str, *, now=None) -> str | None:
    """Why a person may not move ``claim`` to ``to_status`` over its evidence, or
    ``None`` when they may.

    A move the audit would hold back at once is refused rather than made and then
    undone: the claim cannot be read as passing over a contradiction, a load-bearing
    failure, or refused adverse evidence. A withdrawal (REVOKED) is never refused.
    The way through is to resolve the evidence -- invalidate an item, with a reason,
    or record independent evidence that carries weight -- not to choose a reading."""
    if str(to_status) == Status.REVOKED:
        return None
    result = audit_of(claim, base_status=str(to_status), now=now)
    if result is None or not result["held"]:
        return None
    why = "; ".join(result["contradictions"]) or f"the evidence reads {result['verdict']}"
    return _clip(
        f"The evidence recorded against this claim holds it at {result['status']} "
        f"({result['verdict']}): {why} Resolve the evidence first -- invalidate an item "
        "with a reason, or record independent evidence -- rather than choosing a reading."
    )


# ---------------------------------------------------------------------------
# Recording and retiring evidence
# ---------------------------------------------------------------------------


def _strings(value, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
        raise EvidenceRefused(f"{name} must be a list of strings")
    return list(value)


def _choice(value, choices, name: str) -> str:
    if value not in set(choices):
        raise EvidenceRefused(f"{name} {value!r} is not one of {sorted(choices)}")
    return value


@transaction.atomic
def record_claim_evidence(
    claim: AssuranceClaim,
    *,
    outcome: str,
    origin: str,
    evidence_class: str = EvidenceClass.UNKNOWN.value,
    subject_deployment: str = "",
    subject_claim_type: str = "",
    subject_asset: str = "",
    subject_route: str = "",
    subject_inputs: str = "",
    observed_at=None,
    expires_at=None,
    state_check_ref: str = "",
    state_checked_at=None,
    signer: str = "",
    signature_verified: bool = False,
    content_digest: str = "",
    conditions=None,
    residual_uncertainty=None,
    actor_account: str = "",
    actor_account_kind: str = ClaimEvidence.AccountKind.UNKNOWN.value,
    actor_device: str = "",
    actor_organization: str = "",
    actor_human: str = "",
    human_identified_by: str = "",
    areas=None,
    summary: str = "",
    supersedes: ClaimEvidence | None = None,
    recorded_by=None,
    now=None,
) -> ClaimEvidence:
    """Record one evidence object against ``claim``'s identity, then audit it.

    ANYTHING WELL-FORMED IS RECORDED; whether it carries weight is the audit's
    question, asked afresh every time the claim is audited. What is refused here
    (:class:`EvidenceRefused`) is only what cannot be a record at all: an unknown
    origin, outcome, grade or account kind; an outcome of CONTESTED (a property of
    a set, not an item); an area the columns own; a person named with nothing that
    identified them, or identified by the very artifact being attributed; a claim
    that is not current, or withdrawn.

    ``expires_at`` defaults to the observation instant (or now) plus the evidence
    TTL: evidence is never recorded as good forever."""
    now = now or timezone.now()
    if not _is_audited(claim):
        raise EvidenceRefused("evidence is recorded only against a current, unwithdrawn claim version")
    if outcome not in ITEM_OUTCOMES:
        raise EvidenceRefused(f"outcome {outcome!r} is not one an evidence item can carry ({sorted(ITEM_OUTCOMES)})")
    _choice(origin, Origin.values, "origin")
    _choice(evidence_class, EvidenceClass.values, "evidence_class")
    _choice(actor_account_kind, ClaimEvidence.AccountKind.values, "actor_account_kind")

    areas = dict(areas or {})
    extra = set(areas) - CARRIED_AREAS
    if extra:
        raise EvidenceRefused(
            f"areas {sorted(extra)} are read off the record's own fields, not supplied: only "
            f"{sorted(CARRIED_AREAS)} are carried as given"
        )

    actor_human = (actor_human or "").strip()
    human_identified_by = (human_identified_by or "").strip()
    if actor_human and not human_identified_by:
        raise EvidenceRefused(
            "a person is named only with what identified them: an account, a signature or a "
            "service account's action is a traceable artifact, not a person"
        )
    if human_identified_by and human_identified_by in {
        (signer or "").strip(), (actor_account or "").strip(), (content_digest or "").strip()
    } - {""}:
        raise EvidenceRefused(
            "the artifact being attributed cannot be what identifies the person: a signature "
            "or an account names an account, never who was at it"
        )

    if supersedes is not None and (
        supersedes.deployment_id != claim.deployment_id or supersedes.claim_fingerprint != claim.fingerprint
    ):
        raise EvidenceRefused("an item supersedes only evidence recorded against the same claim")

    item = ClaimEvidence.objects.create(
        deployment_id=claim.deployment_id,
        claim_fingerprint=claim.fingerprint,
        recorded_against=claim,
        subject_deployment=str(subject_deployment or ""),
        subject_claim_type=str(subject_claim_type or ""),
        subject_asset=str(subject_asset or ""),
        subject_route=str(subject_route or ""),
        subject_inputs=str(subject_inputs or ""),
        origin=origin,
        signer=signer or "",
        signature_verified=bool(signature_verified),
        content_digest=content_digest or "",
        outcome=outcome,
        evidence_class=evidence_class,
        observed_at=observed_at,
        state_check_ref=state_check_ref or "",
        state_checked_at=state_checked_at,
        conditions=_strings(conditions, "conditions"),
        residual_uncertainty=_strings(residual_uncertainty, "residual_uncertainty"),
        expires_at=expires_at or ((observed_at or now) + timedelta(days=EVIDENCE_TTL_DAYS)),
        actor_account=actor_account or "",
        actor_account_kind=actor_account_kind,
        actor_device=actor_device or "",
        actor_organization=actor_organization or "",
        actor_human=actor_human,
        human_identified_by=human_identified_by,
        recorded_by=recorded_by,
        areas=areas,
        summary=summary or "",
        created_at=now,
    )
    if supersedes is not None:
        # Recorded, not decided: whether the successor retires it is the audit's
        # question (a successor that carries no weight retires nothing).
        ClaimEvidence.objects.filter(pk=supersedes.pk).update(superseded_by=item)
    audit_claim(claim, now=now)
    return item


@transaction.atomic
def invalidate_claim_evidence(item: ClaimEvidence, *, actor, reason: str, now=None) -> ClaimEvidence:
    """Retire an evidence item, attributed and with a reason, and re-audit the
    claim's current version. The only way a person resolves a contradiction: the
    item stays on the record, and the invalidation is an event on it."""
    reason = (reason or "").strip()
    if actor is None:
        raise EvidenceRefused("an invalidation is attributed to the account that made it")
    if not reason:
        raise EvidenceRefused("an invalidation says why")
    if item.invalidated_at is not None:
        raise EvidenceRefused("this evidence was already invalidated")
    now = now or timezone.now()
    item.invalidated_at = now
    item.invalidation_reason = reason
    item.invalidated_by = actor
    item.save(update_fields=["invalidated_at", "invalidation_reason", "invalidated_by"])
    current = (
        AssuranceClaim.objects.filter(deployment_id=item.deployment_id, fingerprint=item.claim_fingerprint)
        .current()
        .first()
    )
    if current is not None:
        audit_claim(current, now=now)
    return item


# ---------------------------------------------------------------------------
# Reading an item back: attribution and the ten record areas
# ---------------------------------------------------------------------------


def attribution(item: ClaimEvidence) -> dict:
    """Account, device, organisation and person, each its own fact.

    ``human`` is named only where something other than the record identified a
    person (``human_identified_by``); a signed commit or a service account's action
    is a traceable artifact of an account. ``personal_intent`` is always
    ``not_established``: no signature, account or identification in an evidence
    record shows what a person meant to do."""
    return {
        "account": item.actor_account or UNKNOWN,
        "account_kind": item.actor_account_kind or ClaimEvidence.AccountKind.UNKNOWN.value,
        "device": item.actor_device or UNKNOWN,
        "organization": item.actor_organization or UNKNOWN,
        "human": item.actor_human or None,
        "human_identified_by": item.human_identified_by or None,
        "signer": item.signer or None,
        "signature_verified": bool(item.signature_verified),
        "reads_as": "identified_person" if item.actor_human else "traceable_artifact",
        "personal_intent": "not_established",
    }


def _iso(value):
    return value.isoformat() if value is not None else UNKNOWN


def evidence_record(item: ClaimEvidence) -> dict:
    """The ten record areas of one evidence object, every one present."""
    carried = item.areas or {}
    invalidation_events = []
    if item.invalidated_at is not None:
        invalidation_events.append(
            {
                "event": "invalidated",
                "at": item.invalidated_at.isoformat(),
                "reason": item.invalidation_reason,
                "by": getattr(item.invalidated_by, "username", None),
            }
        )
    if item.superseded_by_id is not None:
        invalidation_events.append(
            {"event": "superseded", "by_evidence": str(item.superseded_by.uuid)}
        )
    return {
        "identity": {
            "evidence": str(item.uuid),
            "deployment": item.subject_deployment or UNKNOWN,
            "claim_type": item.subject_claim_type or UNKNOWN,
            "component": item.subject_asset or None,
            "served_route": item.subject_route or UNKNOWN,
        },
        "authority": {
            "origin": item.origin,
            "signer": item.signer or None,
            "signature_verified": bool(item.signature_verified),
            "content_digest": item.content_digest or None,
            "integrity_is_not_truth": SIGNATURE_IS_NOT_TRUTH,
        },
        "inputs": {"input_fingerprint": item.subject_inputs or UNKNOWN},
        "action": carried.get("action", UNKNOWN),
        "execution": carried.get("execution", UNKNOWN),
        "observation": {
            "observed_at": _iso(item.observed_at),
            "evidence_class": item.evidence_class,
            "state_check": item.state_check_ref or None,
            "state_checked_at": _iso(item.state_checked_at),
            "summary": item.summary,
        },
        "finding": carried.get("finding", UNKNOWN),
        "responsibility": attribution(item),
        "repair": carried.get("repair", UNKNOWN),
        "claim": {
            "outcome": item.outcome,
            "conditions": list(item.conditions or []),
            "residual_uncertainty": list(item.residual_uncertainty or []),
            "expiry": _iso(item.expires_at),
            "invalidation_events": invalidation_events,
        },
    }
