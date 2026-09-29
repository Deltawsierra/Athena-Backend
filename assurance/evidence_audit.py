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
- it is live: not past its expiry, not invalidated by a person who is attributed
  with it, not retired by a successor (below), observed at a stated instant that
  is not in the future;
- it names THIS claim: this deployment, this claim type, this component (or no
  component, for a deployment-wide claim), the served route serving now, and the
  input fingerprint of the version being audited;
- an INDEPENDENT STATE CHECK backs what it asserts. A verified signature says who
  produced the bytes and that they are unaltered; it says nothing about whether
  the observation in them was true or complete. An item whose only warrant is its
  signature -- or whose "state check" is its own content digest or signer, in
  any spelling -- asserts an effect nobody checked, and is
  ``no_independent_state_check``.

A successor retires what it supersedes only when it asserts pass or fail, carries
weight under every rule above (so it is independent, live, on this subject,
checked and graded -- the bar a pass must meet), and was observed strictly after
the item it supersedes. A successor that asserts nothing, that could not carry
weight, or that saw the subject no later than the item did retires nothing, and
the audit's ``supersessions`` says which it was.

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

- FAIL on load-bearing evidence moves the claim to CONTRADICTED. A claim whose
  own reading is an observed pass (the DERIVER's SUPPORTED or VERIFIED on
  technically or configuration verified, non-vendor evidence) is pass-side
  evidence itself, so a load-bearing fail against it is CONTESTED, not FAIL. A
  person's label is never evidence: a person's SUPPORTED or VERIFIED is not the
  pass side, and a contradiction clears only by an attributed invalidation;
- CONTESTED, or INCOMPLETE because adverse evidence was refused or is partial,
  holds it at UNKNOWN (``confidence`` None);
- PASS and INSUFFICIENT_EVIDENCE move nothing. A PASS is the evidence agreeing
  with the claim; it is not a promotion. Upward moves stay where they were: the
  deriver's reading of the graph, and an attributed human transition -- which is
  refused where it would take the claim ABOVE its reading and this audit would
  hold the target status back (:func:`refusal_for_transition`).

A hold is on the claim's status, never on its reading. A person may always move
the reading down -- a downgrade is recorded as the reading under the hold, which
goes on holding the claim as far as its evidence says -- and may always stop it:
a contradiction or a withdrawal is never refused, whatever the claim reads or is
held at, and does no evidence work (:mod:`assurance.claims`). Refusing either
kept the higher reading under the hold, and a later release landed the claim on
it, above where it would sit had no evidence been recorded.

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

import re
from dataclasses import dataclass
from datetime import timedelta

from django.db import transaction
from django.db.models import Count, Max
from django.utils import timezone
from django.utils.dateparse import parse_datetime

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

#: The most entries of each per-item list the claim's stored audit carries. The
#: lists grow with every item recorded against the claim, and every claim read
#: served them whole (1.1 MB at 10,000 items) -- as did the stop that rewrote the
#: audit to take a hold down. The stored audit is a bounded SUMMARY (``counts`` of
#: each list, ``lists_truncated``), and the whole weighing is kept beside it
#: (:class:`~assurance.models.ClaimAuditWeighing`, its own table), read only for
#: the items a page of the evidence route shows.
AUDIT_LIST_LIMIT = 20
#: The per-item lists of an audit.
AUDIT_LISTS = ("admitted", "refused", "contradictions", "supersessions", "residual_uncertainty")
#: How many items one contradiction line names before it counts the rest.
_NAMED_IN_A_LINE = 10

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
#: An item naming a subject that differs from this claim's only in case or spacing.
#: Subjects bind exactly, so it is not about this claim -- and the audit says it
#: was a near miss rather than letting it weigh nothing silently. Never neutral on
#: its own: the naming reason beside it decides what the item weighs.
SUBJECT_MISMATCH = "subject_mismatch"

# Why a successor did or did not retire the item it supersedes (``supersessions``).
RETIRES = "retires"
SUCCESSOR_ASSERTS_NOTHING = "successor_asserts_nothing"
SUCCESSOR_CARRIES_NO_WEIGHT = "successor_carries_no_weight"
SUCCESSOR_NOT_OBSERVED_LATER = "successor_not_observed_later"
SUCCESSOR_NOT_ON_RECORD = "successor_not_on_record"

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
#: The outcomes that assert an effect: the only ones held to a state check and a
#: grade, and so the only ones a successor may carry to retire what it supersedes.
_ASSERTING = frozenset({ClaimVerdict.PASS.value, ClaimVerdict.FAIL.value})

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

#: A leading hash-algorithm label on a digest: ``sha256:``, ``SHA-512=``, ``md5:``.
_ALGORITHM_PREFIX = re.compile(r"^(?:sha-?(?:1|224|256|384|512)|sha3-(?:224|256|384|512)|blake2[bs]|blake3|md5)[:=]")


def _as_reference(value) -> str:
    """A digest or signer as it is compared: stripped, lower-cased, and without a
    leading algorithm label, so ``SHA256:7F3A9C``, ``7f3a9c`` and ``sha256:7f3a9c``
    are one value. Used only to compare, never stored."""
    text = (value or "").strip().lower()
    return _ALGORITHM_PREFIX.sub("", text, count=1).strip()


def _loose(value) -> str:
    """A subject value with case and whitespace ignored -- only to tell a near miss
    from a different subject. Binding is always on the exact value."""
    return "".join(str(value or "").split()).casefold()


def _attributed_invalidation(item: ClaimEvidence) -> bool:
    """Whether an item's invalidation is one a person is attributed with: the
    account that made it (as it was named at the time) and a reason. Only
    :func:`invalidate_claim_evidence` writes that; a row stamped invalidated any
    other way has retired nothing."""
    return bool((item.invalidated_by_username or "").strip() and (item.invalidation_reason or "").strip())


def _near_misses(item: ClaimEvidence, subject: Subject) -> list[str]:
    """The subject fields ``item`` names that differ from ``subject``'s only in
    case or spacing."""
    pairs = (
        ("deployment", item.subject_deployment, subject.deployment),
        ("claim type", item.subject_claim_type, subject.claim_type),
        ("component", item.subject_asset, subject.asset),
        ("served route", item.subject_route, subject.route),
        ("input fingerprint", item.subject_inputs, subject.inputs),
    )
    return [
        name for name, named, own in pairs
        if named and own and named != own and _loose(named) == _loose(own)
    ]


def _intrinsic_reasons(item: ClaimEvidence, subject: Subject, now) -> list[str]:
    """Every reason ``item`` carries no weight, leaving supersession aside."""
    reasons: list[str] = []

    # Authority: who produced it.
    if item.origin == Origin.TARGET:
        reasons.append(TARGET_AUTHORED)
    elif item.origin != Origin.INDEPENDENT:
        reasons.append(NOT_INDEPENDENT)

    # Liveness. An invalidation retires an item only when a person is attributed
    # with it (see _attributed_invalidation).
    if item.invalidated_at is not None and item.invalidated_at <= now and _attributed_invalidation(item):
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
    if _near_misses(item, subject):
        reasons.append(SUBJECT_MISMATCH)

    # Observation: an asserted effect needs an independent check of the state, and
    # a grade that says how it is known. Integrity is not that check.
    if item.outcome in _ASSERTING:
        check = (item.state_check_ref or "").strip()
        if not check or item.state_checked_at is None:
            reasons.append(NO_INDEPENDENT_STATE_CHECK)
        elif _as_reference(check) in {
            _as_reference(item.content_digest),
            _as_reference(item.signer),
        } - {""}:
            reasons.append(STATE_CHECK_IS_THE_RECORD)
        if item.evidence_class in _UNGRADED_CLASSES:
            reasons.append(UNGRADED)
    return reasons


def classify(items, subject: Subject, now) -> dict[int, list[str]]:
    """``{item.pk: reasons}`` for every item; an empty list means load-bearing.

    Supersession is decided here, across the set: an item is retired by its
    successor only when the successor asserts pass or fail, itself carries weight
    under every admission rule, and observed the subject strictly after the item
    did. A successor the target wrote, one that is stale or unchecked, one that
    asserts nothing, or an older observation filed over a newer one cannot retire
    an independent observation -- or a party could make a contradiction disappear
    by filing over it."""
    return _weigh(items, subject, now)[0]


def _weigh(items, subject: Subject, now) -> tuple[dict[int, list[str]], list[dict]]:
    """:func:`classify`, and each supersession it judged: ``{evidence, successor,
    retired, why}``, ``why`` being :data:`RETIRES` or the reason it did not."""
    items = list(items)
    intrinsic = {item.pk: _intrinsic_reasons(item, subject, now) for item in items}
    by_pk = {item.pk: item for item in items}

    def why_not_retired(item, seen) -> str:
        """Why ``item``'s successor does not retire it, or "" when it does."""
        successor = by_pk.get(item.superseded_by_id)
        if successor is None:
            return SUCCESSOR_NOT_ON_RECORD
        if successor.outcome not in _ASSERTING:
            return SUCCESSOR_ASSERTS_NOTHING
        if not carries_weight(successor.pk, seen + (item.pk,)):
            return SUCCESSOR_CARRIES_NO_WEIGHT
        if item.observed_at is None or successor.observed_at is None or successor.observed_at <= item.observed_at:
            return SUCCESSOR_NOT_OBSERVED_LATER
        return ""

    def carries_weight(pk, seen=()) -> bool:
        item = by_pk.get(pk)
        if item is None or pk in seen or intrinsic[pk]:
            return False
        return item.superseded_by_id is None or bool(why_not_retired(item, seen))

    out: dict[int, list[str]] = {}
    supersessions: list[dict] = []
    for item in items:
        reasons = list(intrinsic[item.pk])
        if item.superseded_by_id is not None:
            why = why_not_retired(item, ())
            if not why:
                reasons.append(SUPERSEDED)
            successor = by_pk.get(item.superseded_by_id)
            supersessions.append(
                {
                    "evidence": str(item.uuid),
                    "successor": str(successor.uuid) if successor is not None else None,
                    "retired": not why,
                    "why": why or RETIRES,
                }
            )
        out[item.pk] = reasons
    return out, supersessions


# ---------------------------------------------------------------------------
# The audit -- a set of items against a claim's reading
# ---------------------------------------------------------------------------


def _base_side(base_status: str, *, vendor_asserted: bool, evidence_class: str, by_person: bool = False) -> str:
    """Which side the claim's own reading stands on: ``pass`` only for a pass the
    platform itself observed (not a vendor's word, not an inference, and not a
    person's label), ``fail`` for a contradicted claim, ``stale`` for an expired
    one, otherwise nothing.

    ``by_person``: the reading is a person's. A person's SUPPORTED or VERIFIED is a
    judgment, never an observation, so it is never the pass side of a
    contradiction. It was, and SUPPORTED ranks with PARTIALLY_VERIFIED: under a
    counted FAIL a person's "lateral" relabel PARTIALLY_VERIFIED -> SUPPORTED turned
    the verdict from fail to contested and the claim from CONTRADICTED to UNKNOWN,
    and back again -- a contradiction cleared by nobody's invalidation."""
    if base_status == Status.CONTRADICTED:
        return "fail"
    if base_status == Status.STALE:
        return "stale"
    if (
        not by_person
        and base_status in (Status.SUPPORTED, Status.VERIFIED)
        and not vendor_asserted
        and evidence_class in _OBSERVED_CLASSES
    ):
        return "pass"
    return ""


def _named(refs: list[str]) -> str:
    """At most :data:`_NAMED_IN_A_LINE` of ``refs``, joined, and how many more."""
    shown = ", ".join(refs[:_NAMED_IN_A_LINE])
    more = len(refs) - _NAMED_IN_A_LINE
    return shown + (f" and {more} more" if more > 0 else "")


def audit(
    *,
    base_status: str,
    vendor_asserted: bool,
    evidence_class: str,
    subject: Subject,
    items,
    now,
    reading_by_person: bool = False,
) -> dict | None:
    """The evidence audit of one claim version, or ``None`` when no evidence was
    recorded against it (nothing to audit: the status is the reading's own).
    ``reading_by_person``: ``base_status`` is a person's reading, which is never
    the pass side (:func:`_base_side`).

    Pure: reads nothing and writes nothing. Returns the stored form
    (:attr:`AssuranceClaim.evidence_audit`): the verdict, the status the claim is
    held at (never above ``base_status``), what carried weight, what was refused
    and why, the contradictions and the residual uncertainty."""
    items = list(items)
    if not items or str(base_status) in _UNAUDITED_STATUSES:
        return None
    reasons, supersessions = _weigh(items, subject, now)

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

    side = _base_side(
        str(base_status), vendor_asserted=vendor_asserted, evidence_class=evidence_class, by_person=reading_by_person
    )
    pass_side = side == "pass" or bool(passes)
    fail_side = side == "fail" or bool(fails)

    contradictions: list[str] = []
    if pass_side and fail_side:
        verdict = ClaimVerdict.CONTESTED
        # The claim's own reading first: a line names only the first few.
        for_ = (["the claim's own reading"] if side == "pass" else []) + [f"evidence {i.uuid}" for i in passes]
        against = (["the claim's own reading"] if side == "fail" else []) + [f"evidence {i.uuid}" for i in fails]
        contradictions.append(
            "Load-bearing evidence disagrees: " + _named(for_) + " reads pass; "
            + _named(against) + " reads fail. Not resolved to either reading."
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
    for i in refused:
        near = _near_misses(i, subject)
        if near:
            residual.append(
                f"Evidence {i.uuid} ({i.outcome}) names a {', '.join(near)} that differs from this "
                "claim's only in case or spacing. Subjects bind exactly, so it weighs nothing here; "
                "check how it was addressed."
            )
    for i in items:
        if i.invalidated_at is not None and not _attributed_invalidation(i):
            residual.append(
                f"Evidence {i.uuid} is marked invalidated, but nobody is attributed with the "
                "invalidation; it is not retired. Only an attributed invalidation with a reason retires evidence."
            )
    if verdict == ClaimVerdict.INSUFFICIENT_EVIDENCE:
        residual.append(
            "No evidence that could carry weight was recorded for this claim; this is "
            "the answer, not a failure and not a pass."
        )

    # Until when this audit is the answer: the first instant an item it counted
    # expires or is retired by an invalidation dated ahead, or a refused item's
    # reason lapses (observed in the future). Past it, the stored audit is not
    # served as current (:func:`audit_is_current`): nothing re-audits on expiry.
    horizons = []
    for i in items:
        if i.invalidated_at is not None and i.invalidated_at > now and _attributed_invalidation(i):
            horizons.append(i.invalidated_at)
    for i in admitted:
        if i.expires_at is not None:
            horizons.append(i.expires_at)
    for i in refused:
        if OBSERVED_IN_THE_FUTURE in reasons[i.pk] and i.observed_at is not None:
            horizons.append(i.observed_at - MAX_CLOCK_SKEW)
    valid_until = min(horizons).isoformat() if horizons else None

    return {
        "verdict": verdict.value,
        "base_status": str(base_status),
        "status": status,
        "held": held,
        "reading_by_person": bool(reading_by_person),
        "valid_until": valid_until,
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
        "supersessions": supersessions,
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
    person put there -- or STALE, where a stale mark reached the reading under the
    hold (:func:`hold_reading_at_stale`). Only while the claim still reads exactly
    what the audit held it at: any other writer since -- a STALE mark, a
    withdrawal, a person -- wrote the reading itself."""
    if _held_by_audit(claim):
        return claim.evidence_audit["base_status"]
    return claim.status


def _held_by_audit(claim: AssuranceClaim) -> bool:
    """Whether ``claim`` stands where the evidence audit holds it, below its reading."""
    audit = claim.evidence_audit or {}
    return bool(audit.get("held") and claim.status == audit.get("status") and audit.get("base_status"))


def _no_more_than(confidence, ceiling):
    """``confidence``, never above ``ceiling``; ``None`` (no supporting confidence)
    is the floor either one can impose."""
    if confidence is None or ceiling is None:
        return None
    return min(confidence, ceiling)


def hold_reading_at_stale(claim: AssuranceClaim, *, note: str) -> bool:
    """A writer that marks a claim STALE -- drift, a fired latent condition -- found
    it held by its evidence at a status it does not soften (CONTRADICTED). The hold
    stands, and the mark reaches the reading UNDER it: the reading is STALE now, so
    whatever later releases the hold lands on STALE, never on the reading from
    before the change.

    It used to stop at the hold: the claim kept its pre-change reading underneath,
    and an invalidation of the evidence lifted it straight back to that reading
    (SUPPORTED, with confidence) while the control, with no evidence at all, read
    STALE. Records a same-status :class:`ClaimEvent` and returns True when it moved
    the reading; False when the claim is not held, or its reading is already no
    pass."""
    if not _held_by_audit(claim):
        return False
    audit = claim.evidence_audit
    if audit["base_status"] in (Status.STALE, Status.CONTRADICTED, Status.REVOKED, Status.SUPERSEDED):
        return False
    claim.evidence_audit = {
        **audit,
        "base_status": Status.STALE.value,
        "base_confidence": None,
        "reading_by_person": False,
        "held": rank(audit["status"]) < rank(Status.STALE),
    }
    claim.save(update_fields=["evidence_audit", "updated_at"])
    ClaimEvent.objects.create(
        claim=claim,
        from_status=claim.status,
        to_status=claim.status,
        actor=None,
        note=_clip(
            f"{note} The evidence still holds the claim at {claim.status}; the reading under "
            f"the hold was {audit['base_status']} and is now stale."
        ),
    )
    return True


def _is_audited(claim: AssuranceClaim) -> bool:
    return claim.valid_to is None and claim.effective_to is None and claim.status not in _UNAUDITED_STATUSES


def audit_of(
    claim: AssuranceClaim,
    *,
    base_status: str | None = None,
    now=None,
    route: str | None = None,
    reading_by_person: bool | None = None,
):
    """:func:`audit` of a stored claim version, reading its evidence and the route
    serving now. ``base_status`` defaults to the claim's own reading, and
    ``reading_by_person`` to whether a person set that reading (read off the
    claim's lifecycle); a caller auditing a person's move passes both."""
    from .served_route import serving_route_now

    now = now or timezone.now()
    items = list(evidence_for(claim))
    if not items:
        return None
    if reading_by_person is None:
        from .claims import _status_set_by_a_person

        reading_by_person = base_status is None and _status_set_by_a_person(claim)
    route = route if route is not None else serving_route_now(claim.deployment)
    return audit(
        base_status=base_status if base_status is not None else reading_status(claim),
        vendor_asserted=claim.vendor_asserted,
        evidence_class=claim.evidence_class,
        subject=subject_of(claim, route=route),
        items=items,
        now=now,
        reading_by_person=reading_by_person,
    )


def audit_summary(result: dict) -> dict:
    """The stored form of an audit on the claim (:attr:`AssuranceClaim.evidence_audit`):
    everything but the per-item lists, which are cut to :data:`AUDIT_LIST_LIMIT`
    entries each, with ``counts`` of every list and ``lists_truncated``. Bounded
    whatever was recorded, so no claim read -- and no stop, which rewrites it to
    take a hold down (:func:`taken_down`) -- grows with the evidence."""
    counts = {key: len(result.get(key) or []) for key in AUDIT_LISTS}
    summary = {key: value for key, value in result.items() if key not in AUDIT_LISTS}
    for key in AUDIT_LISTS:
        summary[key] = list(result.get(key) or [])[:AUDIT_LIST_LIMIT]
    summary["counts"] = counts
    summary["lists_truncated"] = any(n > AUDIT_LIST_LIMIT for n in counts.values())
    return summary


def audit_columns(result: dict | None) -> dict:
    """The claim columns an audit is stored in: the verdict and the bounded summary
    (:func:`audit_summary`). ``None`` is no audit: both empty. The whole weighing
    goes beside them (:func:`store_weighing`)."""
    if result is None:
        return {"evidence_verdict": "", "evidence_audit": {}}
    return {"evidence_verdict": result["verdict"], "evidence_audit": audit_summary(result)}


def store_audit(claim: AssuranceClaim, result: dict | None) -> list[str]:
    """Write ``result`` onto ``claim`` (not saved, :func:`audit_columns`); the
    fields. The caller saves the claim, then :func:`store_weighing`."""
    columns = audit_columns(result)
    for field, value in columns.items():
        setattr(claim, field, value)
    return list(columns)


def weighing_of(result: dict) -> dict:
    """The whole per-item weighing of an audit, as :func:`store_weighing` keeps it."""
    return {key: list(result.get(key) or []) for key in AUDIT_LISTS}


def store_weighing(claim: AssuranceClaim, result: dict | None) -> None:
    """Keep ``result``'s whole per-item weighing beside the saved ``claim``
    (:class:`~assurance.models.ClaimAuditWeighing`); ``None`` removes it. Written
    over the stored one without reading it back (it grows with the evidence)."""
    from .models import ClaimAuditWeighing

    if result is None:
        ClaimAuditWeighing.objects.filter(claim_id=claim.pk).delete()
        return
    items = weighing_of(result)
    if not ClaimAuditWeighing.objects.filter(claim_id=claim.pk).update(items=items, updated_at=timezone.now()):
        ClaimAuditWeighing.objects.create(claim_id=claim.pk, items=items)


def stored_weighing(claim: AssuranceClaim) -> dict:
    """The whole per-item weighing stored beside ``claim``'s audit, ``{}`` where none."""
    from .models import ClaimAuditWeighing

    return ClaimAuditWeighing.objects.filter(claim_id=claim.pk).values_list("items", flat=True).first() or {}


#: How many times an audit taken outside the write lock is taken again because the
#: claim, or the evidence recorded against it, moved before it could be written.
#: Past that it is taken once more under the lock (:func:`audit_claim`).
AUDIT_ATTEMPTS = 5


def claim_token(claim: AssuranceClaim) -> tuple:
    """What a write decided from a read of ``claim`` compares against the row under
    the write lock: equal, and nothing has written the claim since it was read --
    no stop, no person, no supersession, no other audit (every writer moves
    ``updated_at``; the columns a decision reads are compared as well)."""
    return (
        claim.pk,
        claim.status,
        claim.valid_to,
        claim.effective_to,
        claim.updated_at,
        claim.confidence,
        claim.evidence_verdict,
        claim.evidence_audit,
        claim.legal_status,
        claim.input_fingerprint,
        claim.policy_version,
    )


def evidence_token(deployment_id, fingerprint: str | None = None) -> tuple:
    """The evidence recorded against a claim identity (every identity on the
    deployment when ``fingerprint`` is None), as one aggregate read off the index:
    equal, and no item was recorded since. The only evidence read a write takes
    under the lock.

    An invalidation, or a successor's mark on what it supersedes, writes no new item
    -- and needs no token: each is followed by its own audit, which writes the
    claim's row, and a writer reads the claim's row BEFORE the evidence. So either
    the evidence it read already has the change, or the change's audit writes the
    row after this writer read it -- and the writer finds the row moved and reads
    again (:func:`claim_token`)."""
    items = ClaimEvidence.objects.filter(deployment_id=deployment_id)
    if fingerprint is not None:
        items = items.filter(claim_fingerprint=fingerprint)
    agg = items.aggregate(n=Count("pk"), last=Max("pk"))
    return (agg["n"], agg["last"])


def audit_claim(claim: AssuranceClaim, *, now=None) -> dict | None:
    """Audit a CURRENT claim version in place and write the answer onto it.

    Holds the claim back (or releases a hold its evidence no longer supports, back
    to its own reading -- never above it), writes ``evidence_verdict`` and
    ``evidence_audit``, and records any status move as a :class:`ClaimEvent` with
    ``cause`` evidence_audit and no actor. Returns the audit, or ``None`` when the
    claim is not current, is withdrawn, or has no evidence recorded against it.

    A hold keeps the confidence the reading had before it (``base_confidence``),
    and a release restores no more than that: evidence never leaves a claim with
    confidence it would not carry had nothing been recorded against it.

    Decided from the claim's row as COMMITTED, never from the caller's copy: an
    ingest holding a claim it read before a revoke or a contradiction committed
    audited that copy and wrote the answer over the stop -- a withdrawn claim read
    VERIFIED again, a contradicted one VERIFIED above a claim with no evidence
    (round 4, X1). And the evidence is weighed OUTSIDE the write lock: the audit
    reads every item recorded against the identity, and SQLite's write lock is the
    whole database's, so a stop anywhere waited out an audit whose cost grows with
    the evidence. The row is read, the audit taken, and the answer written in a
    short transaction only if neither the row nor the evidence moved meanwhile
    (:func:`claim_token`, :func:`evidence_token`); if either did -- a stop landed --
    it is read and taken again, and the stop is what it reads. The caller's copy is
    brought to the row written."""
    from .claims import _adopt, _locked_row

    now = now or timezone.now()
    for _attempt in range(AUDIT_ATTEMPTS):
        read = AssuranceClaim.objects.select_related("deployment").get(pk=claim.pk)
        if not _is_audited(read):
            _adopt(claim, read)
            return None
        evidence = evidence_token(read.deployment_id, read.fingerprint)
        result = audit_of(read, now=now)
        with transaction.atomic():
            row = _locked_row(read)
            if claim_token(row) == claim_token(read) and evidence_token(row.deployment_id, row.fingerprint) == evidence:
                written = _write_audit(row, result)
                _adopt(claim, row)
                return written
    # Moved under every attempt: taken once more under the lock, from the row as it is.
    with transaction.atomic():
        row = _locked_row(claim)
        written = _write_audit(row, audit_of(row, now=now)) if _is_audited(row) else None
    _adopt(claim, row)
    return written


def _write_audit(claim: AssuranceClaim, result: dict | None) -> dict | None:
    """Write ``result``, the audit of the locked, committed row ``claim``, onto it
    (:func:`audit_claim`)."""
    from .claims import _confidence

    if result is None:
        return None
    old_status = claim.status
    new_status = result["status"]
    # The confidence the reading carried before any hold: the claim's own while it is
    # not held, and what the hold recorded while it is (none, if it recorded none).
    was_held = _held_by_audit(claim)
    reading_confidence = claim.evidence_audit.get("base_confidence") if was_held else claim.confidence
    if result["held"]:
        result = {**result, "base_confidence": reading_confidence}
    fields = [*store_audit(claim, result), "updated_at"]
    store_weighing(claim, result)
    if new_status != old_status:
        claim.status = new_status
        confidence = _confidence(new_status, claim.evidence_class)
        if not result["held"]:
            confidence = _no_more_than(confidence, reading_confidence)
        claim.confidence = confidence
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


#: The take-downs (:mod:`safety.stops`). Never refused, and never audited first.
STOPS = frozenset({Status.CONTRADICTED.value, Status.REVOKED.value})

_NOT_GIVEN = object()


def refusal_for_transition(claim: AssuranceClaim, to_status: str, *, now=None, audited=_NOT_GIVEN) -> str | None:
    """Why a person may not move ``claim`` to ``to_status`` over its evidence, or
    ``None`` when they may. ``audited``: the audit of ``to_status`` as the reading
    (:func:`audit_of`), when the caller already has it.

    Refused is a move ABOVE the claim's reading (:func:`reading_status` -- the one
    under any hold) that the audit would hold back at once: the claim cannot be
    read as passing over a contradiction, a load-bearing failure, or refused
    adverse evidence, and the move is refused rather than made and then undone. So
    is asking for the very reading a hold already keeps, which asks for nothing but
    the hold's release. The way through is to resolve the evidence -- invalidate an
    item, with a reason, or record independent evidence that carries weight -- not
    to choose a reading.

    Never refused: a stop (contradict, revoke), a move to a reading at or below the
    one the claim has now, and any move off a STALE mark (no reading: see below).
    That is recorded as the reading, and the evidence goes on holding the claim back
    as far as it does. Refusing it kept the higher reading under the hold, and the
    release landed the claim on it -- above a claim with no evidence recorded, which
    took the downgrade."""
    to_status = str(to_status)
    if to_status in STOPS:
        return None
    reading = reading_status(claim)
    if reading == Status.STALE:
        # A stale mark is the machine saying a retest is due, not a reading anyone
        # holds: a re-derive replaces it with the deriver's reading, whatever that is
        # (assurance.claims._same_reading). Measured against the mark, a person's
        # move below the deriver's reading read as a raise and was refused -- and the
        # re-derive then lifted the claim to the deriver's reading, above a claim with
        # no evidence, which kept the person's lower one. The move is the reading;
        # the evidence holds it back as far as it does.
        return None
    if _held_by_audit(claim) and to_status == reading:
        return _refusal(claim.evidence_audit)
    if rank(to_status) <= rank(reading) and to_status != reading:
        return None
    if audited is _NOT_GIVEN:
        audited = audit_of(claim, base_status=to_status, now=now, reading_by_person=True)
    if audited is None or not audited["held"]:
        return None
    return _refusal(audited)


def _refusal(result: dict) -> str:
    why = "; ".join(result.get("contradictions") or []) or f"the evidence reads {result.get('verdict')}"
    return _clip(
        f"The evidence recorded against this claim holds it at {result.get('status')} "
        f"({result.get('verdict')}): {why.rstrip('.')}. Resolve the evidence first -- invalidate an "
        "item with a reason, or record independent evidence -- rather than choosing a reading."
    )


def taken_down(audit: dict, stop: str) -> dict:
    """The stored audit of a claim a person just stopped, where it was holding the
    claim: the stop is the reading now -- the new base under the hold -- and nothing
    ranks below it, so the audit holds nothing any more.

    Pure: reads only the stored audit in hand, never the evidence or the route. A
    stop does no evidence work (:mod:`assurance.claims`). Without it, a claim the
    evidence held at CONTRADICTED that a person then contradicted kept the older
    reading under the hold, and a release of the evidence lifted it back there."""
    if not (audit or {}).get("held"):
        return audit
    return {**audit, "base_status": str(stop), "base_confidence": None, "reading_by_person": True, "held": False}


def served_audit(claim: AssuranceClaim) -> dict:
    """The claim's stored audit as a reader serves it: marked ``audit_current`` --
    False, with ``not_current_reason``, when it was taken while the claim read
    something other than it reads now. A stop (and a stale mark) writes the status
    without re-running the audit; that audit is not the claim's verdict, and a
    withdrawal is never audited again. ``{}`` where nothing was audited."""
    audit = dict(claim.evidence_audit or {})
    if not audit:
        return audit
    why = _why_not_current(claim)
    audit["audit_current"] = not why
    if why:
        audit["not_current_reason"] = why
    return audit


def audit_is_current(claim: AssuranceClaim, *, now=None) -> bool:
    """Whether the stored audit is of the claim as it reads now: taken at the
    status the claim reads, and not past the instant it holds until
    (``valid_until``: an item it counted has expired since, or a refused item's
    reason lapsed). Nothing re-audits on expiry, and a stored ``pass`` whose pass
    had expired was served as current while the audit taken now read
    ``incomplete``. An audit that does not say until when it holds is not current."""
    return not _why_not_current(claim, now=now)


def _why_not_current(claim: AssuranceClaim, *, now=None) -> str:
    """Why the stored audit is not current, or "" when it is (:func:`audit_is_current`)."""
    audit = claim.evidence_audit or {}
    if not audit:
        return "nothing was audited"
    was = audit.get("status") or UNKNOWN
    if was != claim.status:
        if claim.status in _UNAUDITED_STATUSES:
            return (
                f"The evidence was last audited while the claim read {was}; the claim is "
                f"{claim.status} now and is never audited again. This is not its verdict."
            )
        return (
            f"The evidence was last audited while the claim read {was}; it reads {claim.status} "
            "now, set by a move that does not re-run the audit (a person's stop, a stale mark). "
            "This is not its verdict; the claim's next audit brings it current."
        )
    if "valid_until" not in audit:
        return (
            "The stored audit does not say until when it holds (it was taken before audits recorded "
            "when their evidence expires). This is not a current verdict; the claim's next audit brings it current."
        )
    until = parse_datetime(audit["valid_until"]) if audit["valid_until"] else None
    if until is not None and until <= (now or timezone.now()):
        return (
            f"The evidence was audited at {audit.get('audited_at') or UNKNOWN}; at {until.isoformat()} an item it "
            "weighed expired or the reason it was refused lapsed, so the audit taken now weighs the evidence "
            "differently. This is not its verdict; the claim's next audit brings it current."
        )
    return ""


def current_verdict(claim: AssuranceClaim) -> str | None:
    """The claim's evidence verdict, or ``None`` where nothing was audited or the
    stored audit is not current (:func:`served_audit`)."""
    if not claim.evidence_verdict or not audit_is_current(claim):
        return None
    return claim.evidence_verdict


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
    TTL: evidence is never recorded as good forever.

    Whether the claim is current and unwithdrawn -- and what the item supersedes --
    is read from the rows as committed, under the write lock, never from the
    caller's copies: an ingest holding a claim it read before a revoke committed
    recorded against it and audited that copy, and the withdrawal was undone
    (round 4, X1a/X1b). The item is written in that short transaction, and the
    claim is then audited from its committed row (:func:`audit_claim`), weighing the
    evidence outside the lock."""
    from .claims import _locked_row

    now = now or timezone.now()
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

    with transaction.atomic():
        row = _locked_row(claim)
        if not _is_audited(row):
            raise EvidenceRefused("evidence is recorded only against a current, unwithdrawn claim version")
        if supersedes is not None:
            supersedes = (
                ClaimEvidence.objects.select_for_update(of=("self",)).filter(pk=supersedes.pk).first()
            )
            if supersedes is None or (
                supersedes.deployment_id != row.deployment_id or supersedes.claim_fingerprint != row.fingerprint
            ):
                raise EvidenceRefused("an item supersedes only evidence recorded against the same claim")
        item = _create_item(
            row, supersedes=supersedes, subject_deployment=subject_deployment,
            subject_claim_type=subject_claim_type, subject_asset=subject_asset, subject_route=subject_route,
            subject_inputs=subject_inputs, origin=origin, signer=signer, signature_verified=signature_verified,
            content_digest=content_digest, outcome=outcome, evidence_class=evidence_class,
            observed_at=observed_at, expires_at=expires_at, state_check_ref=state_check_ref,
            state_checked_at=state_checked_at, conditions=conditions,
            residual_uncertainty=residual_uncertainty, actor_account=actor_account,
            actor_account_kind=actor_account_kind, actor_device=actor_device,
            actor_organization=actor_organization, actor_human=actor_human,
            human_identified_by=human_identified_by, recorded_by=recorded_by, areas=areas, summary=summary,
            now=now,
        )
    audit_claim(claim, now=now)
    return item


def _create_item(
    claim, *, supersedes, subject_deployment, subject_claim_type, subject_asset, subject_route, subject_inputs,
    origin, signer, signature_verified, content_digest, outcome, evidence_class, observed_at, expires_at,
    state_check_ref, state_checked_at, conditions, residual_uncertainty, actor_account, actor_account_kind,
    actor_device, actor_organization, actor_human, human_identified_by, recorded_by, areas, summary, now,
) -> ClaimEvidence:
    """Write one evidence item against the locked, committed row ``claim``
    (:func:`record_claim_evidence`), and mark what it supersedes."""
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
    return item


def invalidate_claim_evidence(item: ClaimEvidence, *, actor, reason: str, now=None) -> ClaimEvidence:
    """Retire an evidence item, attributed and with a reason, and re-audit the
    claim's current version. The only way a person resolves a contradiction: the
    item stays on the record, and the invalidation is an event on it.

    An item already marked invalidated with nobody attributed (a bulk update, a
    restore, a row whose account was gone before 0045 backfilled its name) retired
    nothing -- and was refused here as "already invalidated", so nothing could ever
    retire it. An attributed invalidation now attaches to it: the person and reason
    are this act's, and the earlier mark is kept in the reason. An attributed
    invalidation stands and is never re-attributed.

    Decided from the item's row as committed, under the write lock, never from the
    caller's copy: a copy read before another person's invalidation committed was
    re-attributed to the later person, their reason written over the first
    (round 4, X1c). The claim is then audited from its committed row
    (:func:`audit_claim`), weighing the evidence outside the lock. The caller's copy
    is brought to the row written."""
    reason = (reason or "").strip()
    if actor is None:
        raise EvidenceRefused("an invalidation is attributed to the account that made it")
    if not reason:
        raise EvidenceRefused("an invalidation says why")
    username = (getattr(actor, "username", "") or "").strip()
    if not username:
        raise EvidenceRefused("an invalidation is attributed to an account with a name")
    now = now or timezone.now()
    with transaction.atomic():
        row = ClaimEvidence.objects.select_for_update(of=("self",)).get(pk=item.pk)
        if row.invalidated_at is not None and _attributed_invalidation(row):
            raise EvidenceRefused("this evidence was already invalidated")
        if row.invalidated_at is not None:
            earlier = (row.invalidation_reason or "").strip() or "no reason recorded"
            reason = _clip(
                f"{reason} (attributing an earlier invalidation nobody was attributed with, "
                f"marked {row.invalidated_at.isoformat()}: {earlier})"
            )
        row.invalidated_at = now
        row.invalidation_reason = reason
        row.invalidated_by = actor
        # The name the account had when it acted, kept on the row: the attribution
        # outlives the account (the foreign key is nulled when it is deleted).
        row.invalidated_by_username = username
        row.save(update_fields=["invalidated_at", "invalidation_reason", "invalidated_by", "invalidated_by_username"])
        current = (
            AssuranceClaim.objects.filter(deployment_id=row.deployment_id, fingerprint=row.claim_fingerprint)
            .current()
            .first()
        )
    item.refresh_from_db()
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
                "by": item.invalidated_by_username or None,
                "attributed": _attributed_invalidation(item),
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
