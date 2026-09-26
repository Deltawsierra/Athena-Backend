"""Aggregate a deployment's findings, its assurance claims and its per-workflow
assurance chains into its six-state deployment decision.

Phase 0.5 gave a Deployment a `decision` field and computed it from the live
findings so a scan culminates in a decision-support artifact, not a vulnerability
count. SPINE Stage 1C adds the other half of the loop: a decision now also depends
on the deployment's **current assurance claims**, so a "ready" decision stays
valid only while the claims that support it remain current. When a change
invalidates a claim (SPINE Phase 2 marks it stale and opens a retest obligation),
the decision drops on its own — "it passed six months ago" stops reading as "it is
safe now". Evidence for a human release decision, never the decision itself.

Two independent signals, combined worst-first:

- **Findings** (Phase 0.5) place the deployment by the worst active finding: a
  CRITICAL → NOT_RECOMMENDED, HIGH → NEEDS_REMEDIATION, MEDIUM/LOW →
  READY_RESTRICTED, only-unverified → NEEDS_MORE_EVIDENCE, nothing → READY. A
  deployment with no findings of any status is *unassessed by findings* (``None``).
  An **INVALIDATED** finding does not place the deployment by its recorded
  severity — that premise moved — but counts as a gap, so it reads as "needs more
  evidence" rather than as either a live severity or a clean pass.
- **Claims** (Stage 1C) cap the decision by claim health. A live CONTRADICTED claim
  (an assurance statement the current state falsifies) caps at NEEDS_REMEDIATION; a
  STALE or UNKNOWN claim, or any open retest obligation, caps at
  NEEDS_MORE_EVIDENCE. Supported/verified claims and a deployment with no claims add
  no cap.
- **Workflow chains** (the compositional assurance graph) place the deployment by
  the worst status among its approved business workflows' authority-to-effect
  chains: a VIOLATED chain → NOT_RECOMMENDED, an INCOMPLETE one → AUDIT_INCOMPLETE,
  a NOT_DEMONSTRATED one → NEEDS_MORE_EVIDENCE, all held → READY -- or
  READY_RESTRICTED when any of them holds on an authorization check alone (an
  Achilles permit check shows the gate authorized the action, not that the
  effect happened; owner default, #278). Worst-of-N, never
  coverage-weighted: forty-nine of fifty workflows holding does not make a
  deployment that can move customer records to an unauthorised destination 98%
  safe. :mod:`assurance.composition` is the rule and argues for itself at length;
  :mod:`assurance.workflow_chains` reads the rows and decides the one thing the
  pure rule cannot — that this signal may contribute READY only when the approved
  workflow set is recorded and every workflow in it reported, so ONE held chain
  cannot make an otherwise-unassessed deployment ready.

- **Accepted risks** (owner decision Q6) cap the decision. A finding a person has
  accepted is a risk the deployment carries for a stated time, not one that went
  away: while every acceptance stands the decision is READY_RESTRICTED at best, and
  an acceptance that has lapsed -- or never named an end -- caps it at
  NEEDS_MORE_EVIDENCE. Accepted findings used to leave the decision entirely, so an
  accepted critical finding read READY.

The decision is the **worse** of them. The claim cap can only hold a decision back
or leave it, never improve it (the same weakest-link discipline the evidence model
keeps): a green finding set cannot paper over a contradicted claim, and a
contradicted claim cannot make a critical finding look better. The decision is
``None`` — *no decision* — only when no signal has assessed anything; an absent
decision is never READY. ``paused`` (the operator failsafe) still overrides
everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from django.db import transaction
from django.utils import timezone

from .coverage import complete_audit_signal, coverage_decision_cap, coverage_manifest
from .composition import READY as composition_READY
from .composition import compose as compose_chains
from .composition import Composition
from .composition import explain as explain_composition
from .observed_outcomes import READ_KEYRING as _READ_KEYRING
from .workflow_chains import (
    composition_decision_signal,
    composition_for,
    composition_payload,
    read_chain_provenance,
)
from .models import (
    UNTRUSTED_SEVERITY_STATUSES,
    RESOLVED_FINDING_STATUSES,
    AssuranceClaim,
    Deployment,
    EvidenceClass,
    Finding,
    LegalStatus,
    RetestRequirement,
    SEVERITY_ORDER,
    severity_rank,
)

# Findings in these states no longer count against a deployment's readiness.
# The one definition lives in ``assurance.models`` beside the statuses themselves.
# Seven modules each kept their own copy of this set, and every one of their
# comments said it "mirrors" the others so every view would agree on what "active"
# means -- which is precisely the arrangement that lets them stop agreeing. Adding
# a status meant editing eight places and silently disagreeing if you missed one.
_RESOLVED_STATUSES = RESOLVED_FINDING_STATUSES

# Evidence classes that mean "we genuinely do not know this" — they drive
# "Requires additional evidence" rather than a clean pass. This is deliberately
# NARROWER than the Unknowns Register's unverified set (which also includes
# ``partially_verified``): a partially-verified finding carries a severity that
# already places the deployment (READY_RESTRICTED and up), so it does not also
# need this info-severity fallback state — whereas the register still tracks it
# as a gap to confirm. The two serve different axes (how bad vs. how sure) and
# only truly-unknown evidence, with no severity to place it, lands here.
_UNVERIFIED = frozenset({EvidenceClass.UNKNOWN, EvidenceClass.NOT_DOCUMENTED})

# Readiness order, best (0) to worst. "Worse" wins when the two signals combine,
# and a cap is a floor on how bad the decision must be — never a ceiling that could
# improve it. PAUSED is worst because a paused engine is not deploying at all.
_READINESS_ORDER = (
    Deployment.Decision.READY,
    Deployment.Decision.READY_RESTRICTED,
    Deployment.Decision.NEEDS_MORE_EVIDENCE,
    # Worse than NEEDS_MORE_EVIDENCE and better than NEEDS_REMEDIATION. Both of the
    # first two are "we do not know", and a coverage gap is the wider of them: weak
    # evidence at least has a subject, whereas an unassessed component could hold
    # anything. But "we found something bad" still outranks "we did not look
    # everywhere" -- a critical finding is a fact, not a gap.
    Deployment.Decision.AUDIT_INCOMPLETE,
    Deployment.Decision.NEEDS_REMEDIATION,
    Deployment.Decision.NOT_RECOMMENDED,
    Deployment.Decision.PAUSED,
)
_READINESS_RANK = {state: rank for rank, state in enumerate(_READINESS_ORDER)}


def _worse(a: str | None, b: str | None) -> str | None:
    """The worse (less ready) of two decision states, ``None``-safe. ``None`` is
    "not assessed by this signal" and never wins over a real state."""
    if a is None:
        return b
    if b is None:
        return a
    return a if _READINESS_RANK[a] >= _READINESS_RANK[b] else b


def _decision_from_findings(deployment: Deployment) -> str | None:
    """The six-state decision implied by a deployment's active findings (Phase 0.5).

    ``None`` when the deployment has no findings of any status — unassessed by
    findings, which is not the same as a deployment whose findings are all resolved
    (genuinely READY)."""
    if not deployment.findings.exists():
        return None

    active = list(
        deployment.findings.exclude(status__in=_RESOLVED_STATUSES).prefetch_related("evidence")
    )

    worst_rank = -1
    has_unverified = False
    for f in active:
        if f.status in UNTRUSTED_SEVERITY_STATUSES:
            # An INVALIDATED finding was assessed and then the ground moved. Its
            # recorded severity is a number the evidence no longer supports, so it
            # does not place the deployment -- but it is not resolved either, and
            # dropping it would hand back a clean bill nobody established. It
            # counts as a gap: "needs more evidence", the same as truly unknown
            # evidence.
            has_unverified = True
            continue
        rank = severity_rank(f.severity)
        if rank > worst_rank:
            worst_rank = rank
        if f.evidence_class in _UNVERIFIED:
            has_unverified = True

    if worst_rank >= severity_rank("critical"):
        return Deployment.Decision.NOT_RECOMMENDED
    if worst_rank >= severity_rank("high"):
        return Deployment.Decision.NEEDS_REMEDIATION
    if worst_rank >= severity_rank("low"):
        # A medium or low active finding is deployable with named restrictions.
        return Deployment.Decision.READY_RESTRICTED
    # Nothing of low+ severity is open. If what remains is only unverified
    # (info-severity but unknown evidence), the honest answer is "need more
    # evidence", not a clean pass.
    if has_unverified:
        return Deployment.Decision.NEEDS_MORE_EVIDENCE
    return Deployment.Decision.READY


#: The legal-axis value a person's recorded materiality judgment leaves a claim in
#: (:func:`assurance.legal.record_materiality_decision`), and the only one that caps.
_LEGALLY_STALE = frozenset({LegalStatus.STALE})


def claim_decision_signal(deployment: Deployment) -> dict:
    """How the deployment's CURRENT assurance claims bear on its decision (Stage 1C).

    Reads the current version of each claim (``valid_to`` null), excluding human
    REVOKED withdrawals (a claim the human took out of scope is neither support nor
    a mark against readiness), plus the deployment's open retest obligations. Returns
    the claims bucketed by how they bear on readiness and the cap they impose:

    - a live **CONTRADICTED** claim caps at NEEDS_REMEDIATION — the current state
      falsifies an assurance statement, and that is not deployable without work;
    - a **STALE** or **UNKNOWN** claim, or any **open retest obligation**, caps at
      NEEDS_MORE_EVIDENCE — the supporting evidence is expired, unproven, or pending
      a retest, so a clean pass is not earned;
    - a claim a person has judged **legally STALE** (:mod:`assurance.legal`) caps at
      NEEDS_MORE_EVIDENCE too, whatever its technical status: an obligation beneath
      it moved and a person recorded that the move is material here, so it needs
      re-assessing on legal grounds. Only that recorded judgment caps -- a review
      merely PENDING is the trigger flagging, and the trigger never judges;
    - SUPPORTED / VERIFIED / PARTIALLY_VERIFIED claims (and DRAFT, which is not yet
      an assessment) impose no cap.

    ``cap`` is ``None`` when no current claim holds the decision back — including a
    deployment with no claims at all, so the finding-based decision governs
    unchanged. The cap never *improves* a decision.
    """
    Status = AssuranceClaim.ClaimStatus
    current = list(
        deployment.assurance_claims.current().exclude(status=Status.REVOKED)
    )
    retest_pending = RetestRequirement.objects.filter(
        deployment=deployment, resolved_at__isnull=True
    ).exists()

    contradicted = [c for c in current if c.status == Status.CONTRADICTED]
    stale = [c for c in current if c.status == Status.STALE]
    unknown = [c for c in current if c.status == Status.UNKNOWN]
    legally_stale = [c for c in current if c.legal_status in _LEGALLY_STALE]
    supporting = [
        c
        for c in current
        if c.status in (Status.SUPPORTED, Status.VERIFIED, Status.PARTIALLY_VERIFIED)
    ]

    if contradicted:
        cap = Deployment.Decision.NEEDS_REMEDIATION
    elif stale or unknown or retest_pending or legally_stale:
        cap = Deployment.Decision.NEEDS_MORE_EVIDENCE
    else:
        cap = None

    return {
        "cap": cap,
        "has_claims": bool(current),
        "retest_pending": retest_pending,
        "contradicted": contradicted,
        "stale": stale,
        "unknown": unknown,
        "legally_stale": legally_stale,
        "supporting": supporting,
    }


def accepted_risk_signal(deployment: Deployment, *, now) -> dict:
    """How the risks a person has accepted bear on the decision (owner decision Q6).

    An accepted finding is resolved for every deriver -- nobody re-opens a risk a
    person chose to carry -- but it is not resolved for the decision. It used to
    be: acceptance took the finding out of the decision altogether, so accepting a
    critical finding read READY, the same answer as fixing it.

    - An acceptance that STANDS (its ``risk_accepted_until`` is after ``now``)
      caps the decision at READY_RESTRICTED: deployable, with a named risk
      carried, never a clean READY.
    - An acceptance that has LAPSED, or never named an end, caps it at
      NEEDS_MORE_EVIDENCE: the decision to carry the risk no longer stands, and
      until a person decides again nobody has.
    - So does an acceptance OUTGROWN: the finding is now more severe than the
      severity it was accepted at (``risk_accepted_severity``), or the acceptance
      does not say what severity it covered. A next scan reporting the same
      signature as critical refreshes the severity and leaves the status alone,
      and a medium someone chose to carry is not a critical they chose to carry.

    ``valid_until`` is the earliest moment a standing acceptance lapses, which is
    when the decision stops being the one its inputs imply without any write --
    recorded with the decision so the first read after it recomputes
    (:func:`current_decision`). ``None`` when nothing here expires.
    """
    accepted = list(
        deployment.findings.filter(status=Finding.Status.ACCEPTED).only(
            "uuid", "title", "severity", "risk_accepted_until", "risk_accepted_severity"
        )
    )
    standing = [
        f
        for f in accepted
        if f.risk_accepted_until is not None
        and f.risk_accepted_until > now
        and _acceptance_covers(f)
    ]
    lapsed = [f for f in accepted if f not in standing]
    if lapsed:
        cap = Deployment.Decision.NEEDS_MORE_EVIDENCE
    elif standing:
        cap = Deployment.Decision.READY_RESTRICTED
    else:
        cap = None
    return {
        "cap": cap,
        "standing": standing,
        "lapsed": lapsed,
        "valid_until": min((f.risk_accepted_until for f in standing), default=None),
    }


def _acceptance_covers(finding: Finding) -> bool:
    """Whether the severity accepted covers the finding's severity now. An
    acceptance that recorded none covers nothing, and a severity this platform does
    not rank is not shown to be within one it does."""
    accepted_at = (finding.risk_accepted_severity or "").strip().lower()
    current = (finding.severity or "").strip().lower()
    if accepted_at not in SEVERITY_ORDER or current not in SEVERITY_ORDER:
        return False
    return severity_rank(current) <= severity_rank(accepted_at)


def _no_accepted_risk() -> dict:
    return {"cap": None, "standing": [], "lapsed": [], "valid_until": None}


def _completed_scan_signal(deployment: Deployment) -> str | None:
    """READY once a scan has run to completion against this deployment, else ``None``.

    Folded into the finding signal with :func:`_worse`, so it is a floor and not a
    cap: it lifts an unassessed deployment to READY and cannot make any real state
    look better. The distinction it carries is the one the finding count cannot --
    "a scan finished and found nothing" versus "nothing has ever been scanned"."""
    if deployment.last_complete_scan_at is None:
        return None
    return Deployment.Decision.READY


def incomplete_evidence_cap(deployment: Deployment) -> str | None:
    """The cap a deployment's *unfinished* latest scan imposes, or ``None``.

    A scan the engine stopped early (the operator hit the failsafe, a ceiling
    tripped) leaves the deployment assessed by a fraction of the work, and the
    scanners that did not run are the ones that would have found the rest. So
    partial evidence caps at NEEDS_MORE_EVIDENCE: it can hold a decision back,
    never improve one. Nothing about it is a finding, which is why the finding
    signal alone could read a stopped scan as READY."""
    if deployment.evidence_incomplete:
        return Deployment.Decision.NEEDS_MORE_EVIDENCE
    return None


@dataclass(frozen=True)
class DecisionParts:
    """Every input a decision is computed from, read once.

    This exists because reading them twice is a bug with no symptom. A caller that
    wants the decision *and* the reasoning behind it -- which is the whole job of
    :func:`decision_support` -- used to read each input once for the payload and
    then call :func:`compute_decision`, which read all of them again. Between the
    two reads a writer can land, and the answer is then stitched from two moments:
    ordinary-looking, internally impossible, and indistinguishable from a real one.

    Reproduced before this change: 81 samples of ``decision_support`` against a
    concurrent writer whose every write was atomic returned four distinct shapes,
    two of which no single database state can produce -- three contradicted claims
    beside ``decision=None`` (three contradicted claims force a cap), and a clean
    claim set beside ``needs_remediation`` (nothing was left to impose one).

    Frozen because these are facts as of one read, not a mutable scratchpad.
    """

    from_findings: str | None
    completed_scan: str | None
    complete_audit: str | None
    claim_signal: dict
    scan_cap: str | None
    coverage_cap: str | None
    # The per-workflow assurance chains, composed by `assurance.composition`'s
    # rule and narrowed by `workflow_chains.composition_decision_signal`. The
    # whole `Composition` rather than just the signal, because `decision_support`
    # reports the census and the deciding workflows, and reading those a second
    # time is the tear this dataclass exists to close.
    composition: Composition
    # Where those chains' outcomes came from. Part of the same read for the
    # same reason: a provenance census from a later moment, published beside
    # this composition, would describe a graph nobody ever had. It takes no
    # part in the decision -- `decide` never reads it -- and is carried here
    # only so the payload can report it without a second read.
    chain_provenance: dict
    # The risks a person has accepted (:func:`accepted_risk_signal`), read at the
    # same moment as everything else -- including the clock it was read against,
    # which is what makes an acceptance standing or lapsed.
    accepted_risk: dict = field(default_factory=_no_accepted_risk)


def read_decision_parts(deployment: Deployment, *, keyring=_READ_KEYRING, now=None) -> DecisionParts:
    """Read every decision input, in one pass.

    Wrapped in a transaction by callers that need the set to be consistent. The
    transaction narrows the window; reading each fact exactly once is what closes
    the demonstrated tear, and it does so at any isolation level -- on READ
    COMMITTED a second read of the same fact is a second moment even inside one
    transaction, so "read it once" is the load-bearing half.
    """
    return DecisionParts(
        from_findings=_decision_from_findings(deployment),
        completed_scan=_completed_scan_signal(deployment),
        complete_audit=complete_audit_signal(deployment),
        claim_signal=claim_decision_signal(deployment),
        scan_cap=incomplete_evidence_cap(deployment),
        coverage_cap=coverage_decision_cap(deployment),
        composition=composition_for(deployment, keyring),
        # Read here with everything else, inside the caller's transaction, for
        # the reason the docstring above gives: reading each fact exactly once
        # is what closes the tear. A census read later would describe a
        # different moment from the composition it is published beside.
        chain_provenance=read_chain_provenance(deployment),
        accepted_risk=accepted_risk_signal(deployment, now=now or timezone.now()),
    )


def decide(parts: DecisionParts) -> str | None:
    """The decision those parts imply. Pure: no reads, no writes, no clock."""
    # A completed scan is an assessment even when it found nothing, so it enters
    # as READY and `_worse` does the rest: it can only turn "nothing has assessed
    # this" into READY, never improve a real finding-based state. Without it a
    # deployment scanned clean read as "not yet assessed", which is the same
    # answer as a deployment nobody ever scanned.
    base = _worse(
        _worse(
            _worse(parts.from_findings, parts.completed_scan),
            # A complete audit that found nothing is an assessment too, and the reason
            # coverage is recorded rather than only reported: without it, a deployment
            # whose every declared component was assessed clean has no findings and so
            # reads as unassessed -- indistinguishable from one nobody has looked at.
            parts.complete_audit,
        ),
        # The compositional assurance graph: what the deployment's per-workflow
        # authority-to-effect chains establish, composed worst-of-N by
        # `assurance.composition`. It enters through `_worse` like the other two
        # assessments, and it can only be READY here when the approved workflow set
        # is recorded and fully reported -- `composition_decision_signal` returns
        # None otherwise, precisely so one held chain cannot make an unassessed
        # deployment ready. A chain that VIOLATES sets NOT_RECOMMENDED, and this is
        # the only signal that can: a deployment producing an effect its authority
        # does not cover is a fact about the deployment, not a doubt about it.
        composition_decision_signal(parts.composition),
    )
    cap = parts.claim_signal["cap"]
    accepted_cap = parts.accepted_risk["cap"]
    # Coverage of the system, not strength of the evidence: something the customer
    # declared, or something flagged high risk, was never assessed at all. Every
    # fact gathered can be genuine and the audit still be incomplete.
    if (
        base is None
        and cap is None
        and parts.scan_cap is None
        and parts.coverage_cap is None
        and accepted_cap is None
    ):
        # Assessed by nothing at all: genuinely no decision.
        return None
    # A risk a person accepted is a cap like the others: it holds the decision back,
    # never lifts it.
    return _worse(_worse(_worse(_worse(base, cap), parts.scan_cap), parts.coverage_cap), accepted_cap)


def compute_decision(
    deployment: Deployment,
    *,
    paused: bool = False,
    parts: DecisionParts | None = None,
    keyring=_READ_KEYRING,
) -> str | None:
    """The six-state decision implied by a deployment's active findings, its
    current assurance claims (Stage 1C), whether its latest scan finished, and
    what its approved workflows' assurance chains establish.

    The decision is the *worse* of the finding-based signal, the claim-based cap,
    the incomplete-evidence cap and the compositional chain signal
    (:mod:`assurance.composition`, read by :mod:`assurance.workflow_chains`). ``paused`` (the operator failsafe, passed by
    the caller) overrides everything. Returns ``None`` — no decision — only when
    nothing has assessed the deployment; an absent decision is never READY.

    ``parts`` lets a caller that has already read the inputs hand them over
    instead of having them read a second time. That is not an optimisation: two
    reads of the same fact are two moments, and a caller reporting both the
    decision and its reasoning must report one moment or neither.
    """
    if paused:
        # Nothing is read at all: the failsafe decides, so no fact about the
        # deployment can change the answer.
        return Deployment.Decision.PAUSED
    return decide(parts if parts is not None else read_decision_parts(deployment, keyring=keyring))


def _claim_brief(claim: AssuranceClaim) -> dict:
    """The minimal, non-sensitive identity of a claim for a decision-support view —
    what it is and where it stands, no raw evidence."""
    return {
        "uuid": str(claim.uuid),
        "claim_type": claim.claim_type,
        "status": claim.status,
        "statement": claim.statement,
    }


def _accepted_brief(finding: Finding) -> dict:
    """An accepted finding for the decision-support view: what it is, how severe,
    and when its acceptance ends (``None`` for one that never named an end)."""
    until = finding.risk_accepted_until
    return {
        "uuid": str(finding.uuid),
        "title": finding.title,
        "severity": finding.severity,
        "accepted_until": until.isoformat() if until else None,
    }


#: A composition that assessed nothing, used to ask what the decision would be
#: WITHOUT the chain signal. `decision_support` needs that counterfactual to say
#: whether the chains are the binding constraint or merely agree with something
#: else, and a note that says "the chains place it there" when the findings
#: already did is the kind of near-miss sentence an operator acts on wrongly.
#: Pure and constant: `compose([])` reads nothing and calls no clock.
_NO_CHAINS: Composition = compose_chains([])


def decision_support(deployment: Deployment, *, paused: bool | None = None) -> dict:
    """The deployment's decision with *why* — the honest decision-support artifact
    (Stage 1C). Shows the final decision, the finding-based signal and the claim cap
    that combined into it, and exactly which current claims support or undermine it,
    so a reader can see that a READY decision stands only while its claims stay
    current.

    A read-only computed view; it does not persist anything.

    Every input is read ONCE, inside one transaction, and the decision is derived
    from that one read rather than recomputed from a second one. This function is
    the artifact the roadmap's "no torn read" bar is about -- it returns the
    decision *and the claims behind it*, which is exactly the pair that must not
    come from two moments -- and it was the one place doing it twice.

    The revision the parts were read at rides in the payload so a consumer can
    fence its own next read (``assurance.revision.read_decision(at_least=...)``).
    Before this, the fence existed only for in-process Python callers: nothing over
    HTTP could tell a fresh answer from a stale one.

    ``paused``: ``None`` -- the default, and the only reading fit to publish --
    takes the operator's pause from the same row, in the same statement, as the
    revision. ``True``/``False`` impose one instead, which is a what-if: the
    revision in the payload is still the row's, so it no longer names the pause
    the body was computed under.

    The row's decision IN FORCE: a row behind its own transition log is read as
    the log records it (:func:`assurance.revision.published_decision`), and that
    is where the pause comes from. Read off the stale row, a pause the log holds
    was published as ``paused: False`` and a live READY. Nothing is written here
    to repair it -- that is :func:`current_decision`'s, through the one writer.
    """
    # Lazy import: assurance.policy imports the decision rules from THIS module, so
    # a top-level import here would be circular.
    from .policy import policy_pin
    from .revision import published_decision

    with transaction.atomic():
        parts = read_decision_parts(deployment)
        # Read inside the same transaction as the parts, so the revision names the
        # moment the parts describe rather than a later one. The pause is the
        # stored decision, so it comes from this same row read too: the route used
        # to take it from the instance it loaded BEFORE this transaction, and a
        # pause committed in between was published as a live READY under the
        # revision that records the pause.
        row = published_decision(deployment.pk)
    stored, revision = row if row is not None else (None, None)
    if paused is None:
        paused = stored == Deployment.Decision.PAUSED
    signal = parts.claim_signal
    from_findings = None if paused else parts.from_findings
    scan_cap = None if paused else parts.scan_cap
    coverage_cap = None if paused else parts.coverage_cap
    # Nulled under `paused` like the other signals, for the same reason: the
    # failsafe decides, so no signal contributed to THIS decision. The census
    # below is NOT nulled -- a paused deployment's violated chain is still a
    # violated chain, and hiding it would be the silent zero with a good excuse.
    chain_signal = None if paused else composition_decision_signal(parts.composition)
    decision = compute_decision(deployment, paused=paused, parts=parts)
    # What the decision would be if the chains had said nothing. Not an
    # optimisation: it is the only way to tell a chain that SET the decision from
    # one that agrees with a finding that already had.
    without_chains = None if paused else decide(replace(parts, composition=_NO_CHAINS))
    chains_are_binding = not paused and decision != without_chains
    # The same counterfactual for the risks a person accepted: they are named as
    # the reason only when they are what holds the decision where it is.
    accepted = parts.accepted_risk
    accepted_cap = None if paused else accepted["cap"]
    without_acceptance = None if paused else decide(replace(parts, accepted_risk=_no_accepted_risk()))
    acceptance_is_binding = not paused and decision != without_acceptance

    if paused:
        note = "Operator failsafe is paused; the deployment is not deploying regardless of findings or claims."
    elif (
        chain_signal == Deployment.Decision.READY_RESTRICTED
        and parts.composition.decision == composition_READY
        and parts.composition.authorization_checked
        and chains_are_binding
    ):
        # Every approved workflow holds, and the chains alone place the deployment
        # here -- restricted, because some of what holds is a permit check. Its own
        # sentence: the generic one below says the chains "place it there" without
        # saying why a composition whose every chain held is not READY.
        note = (
            f"Ready with restrictions: every one of the {parts.composition.workflows_expected} "
            f"approved workflow(s) has a chain outcome and all of them hold, but "
            f"{len(parts.composition.authorization_checked)} hold on an authorization check "
            "alone -- the gate authorized the action at dispatch, and no record shows the "
            f"effect happened within that authority. {explain_composition(parts.composition)}"
        )
    elif chain_signal is not None and chain_signal != composition_READY and chains_are_binding:
        # The per-workflow chains, and nothing else, place the deployment here --
        # `chains_are_binding` is what earns the "not" in the sentence. Without the
        # counterfactual this branch fired whenever the chains merely AGREED with the
        # finding signal, and told the operator to go look at workflow chains for a
        # decision the findings had already made.
        note = (
            f"{explain_composition(parts.composition)} Approved-workflow chains, not "
            f"findings or claims, place it there: without them this deployment would "
            f"read {without_chains or 'not yet assessed'}."
        )
    elif coverage_cap is not None and decision == Deployment.Decision.AUDIT_INCOMPLETE:
        manifest = coverage_manifest(deployment)
        note = (
            f"Held at 'audit incomplete': {manifest['summary']}. Parts of the system "
            "were never assessed, so every fact gathered here can be genuine and the "
            "assessment still be short."
        )
    elif acceptance_is_binding and accepted["lapsed"]:
        titles = ", ".join(sorted(f.title for f in accepted["lapsed"]))
        note = (
            f"Held at 'needs more evidence' by {len(accepted['lapsed'])} accepted risk(s) "
            f"whose acceptance has lapsed or never named an end ({titles}). Accepting a "
            "risk is a decision to carry it for a stated time; past that time nobody "
            "has decided to carry it."
        )
    elif acceptance_is_binding:
        titles = ", ".join(sorted(f.title for f in accepted["standing"]))
        note = (
            f"Ready with restrictions: {len(accepted['standing'])} risk(s) accepted until "
            f"{accepted['valid_until'].isoformat()} at the earliest ({titles}). An accepted "
            "risk is carried, not removed; when its acceptance lapses the decision needs "
            "more evidence."
        )
    elif scan_cap is not None and _worse(from_findings, signal["cap"]) != decision:
        note = (
            "Held at 'needs more evidence' because the latest scan stopped before "
            "it finished; the scanners that did not run are not accounted for, so "
            "this is not a clean result."
        )
    elif signal["cap"] and _worse(from_findings, signal["cap"]) == signal["cap"] and from_findings != signal["cap"]:
        held = ", ".join(sorted({c.claim_type for c in signal["contradicted"] + signal["stale"] + signal["unknown"]}))
        if signal["contradicted"]:
            note = f"Held at 'needs remediation' by a contradicted assurance claim ({held}); a current claim's boundary does not hold."
        elif not (signal["stale"] or signal["unknown"] or signal["retest_pending"]):
            legal = ", ".join(sorted({c.claim_type for c in signal["legally_stale"]}))
            note = (
                f"Held at 'needs more evidence' by a claim a person judged legally stale ({legal}); "
                "an obligation beneath it moved materially, and it needs re-assessing on legal grounds."
            )
        else:
            reason = "an open retest obligation" if signal["retest_pending"] and not (signal["stale"] or signal["unknown"]) else f"a stale or unproven claim ({held})"
            note = f"Held at 'needs more evidence' by {reason}; supporting evidence is not current."
    elif decision == Deployment.Decision.READY and signal["supporting"]:
        # The partially-verified ones are counted SEPARATELY. They impose no cap
        # -- an unreadable reference is a limit on the measurement, not a defect
        # to remediate -- but folding them silently into one "supported by N"
        # tells the operator that N claims stand behind this, when one of them
        # was established over a graph it could not read whole. The decision is
        # right; the sentence about it has to be right too.
        partial = [c for c in signal["supporting"] if c.status == AssuranceClaim.ClaimStatus.PARTIALLY_VERIFIED]
        if partial:
            note = (
                f"Ready, and supported by {len(signal['supporting'])} current assurance claim(s) "
                f"with no open retest — {len(partial)} of them only partially verified "
                f"({', '.join(sorted(c.claim_type for c in partial))}), measured over a graph "
                "part of which could not be read."
            )
        else:
            note = f"Ready, and supported by {len(signal['supporting'])} current assurance claim(s) with no open retest."
    elif chain_signal == composition_READY and chains_are_binding:
        # READY that came from the chains rather than from a scan or a claim. Before
        # this the sentence fell through to "Decision reflects the deployment's
        # active findings", which for a deployment with no findings at all is a
        # statement about nothing, offered as the reason.
        note = (
            f"Ready: every one of the {parts.composition.workflows_expected} approved "
            f"workflow(s) has a chain outcome and all of them hold. "
            f"{explain_composition(parts.composition)}"
        )
    elif decision is None:
        note = "Not yet assessed: no findings, no assurance claims and no workflow chains."
    else:
        note = "Decision reflects the deployment's active findings; no current claim holds it back."

    return {
        "decision": decision,
        "decision_label": Deployment.Decision(decision).label if decision else None,
        # The monotonic revision the whole payload was read at. A consumer that
        # acts on this answer can pass it back as `at_least` and be told, rather
        # than guess, whether what it is holding has been superseded.
        "revision": revision,
        "from_findings": from_findings,
        "claim_cap": signal["cap"],
        "coverage_cap": coverage_cap,
        "accepted_risk_cap": accepted_cap,
        # Every risk a person has accepted, standing or lapsed, with the moment
        # each acceptance ends. Reported even when it is not what binds the
        # decision: a carried risk is part of what the decision rests on.
        "accepted_risk": {
            "standing": [_accepted_brief(f) for f in accepted["standing"]],
            "lapsed": [_accepted_brief(f) for f in accepted["lapsed"]],
            "valid_until": accepted["valid_until"].isoformat() if accepted["valid_until"] else None,
        },
        # The compositional assurance graph, reported rather than only decided
        # with. Shaped by `workflow_chains.composition_payload` because the ingest
        # routes publish the same block, and two hand-written copies of one shape
        # are two things that can disagree about the same deployment.
        "composition": composition_payload(
            parts.composition,
            signal=chain_signal,
            provenance=parts.chain_provenance,
        ),
        "paused": paused,
        # The assurance policy this decision is made under — pinned so a later
        # change to the rules can tell whether the policy still holds.
        "policy_version": policy_pin(deployment),
        "claims": {
            "has_claims": signal["has_claims"],
            "retest_pending": signal["retest_pending"],
            "contradicted": [_claim_brief(c) for c in signal["contradicted"]],
            "stale": [_claim_brief(c) for c in signal["stale"]],
            "unknown": [_claim_brief(c) for c in signal["unknown"]],
            "legally_stale": [_claim_brief(c) for c in signal["legally_stale"]],
            "supporting": [_claim_brief(c) for c in signal["supporting"]],
        },
        "note": note,
    }


def recompute_decision(deployment: Deployment, *, paused: bool | None = None) -> str | None:
    """Compute and persist the deployment's decision. Returns the new decision
    (``None`` for a deployment neither findings nor claims have assessed).

    The write goes through :func:`assurance.revision.accept_transition` rather
    than a bare save, so the decision, its monotonic revision and the transition
    recording the move all commit together. Before that, the decision moved on its
    own: a consumer reading it alongside the claims behind it could catch the two
    from different moments, and the result was an ordinary-looking answer
    assembled from a state that never existed.

    Computed UNDER the row lock, from inside the transaction that writes it. It was
    computed first and written after, so a signed violation recorded between the
    two was overwritten by the READY computed before it arrived, and an operator's
    pause committed in between was lifted by a caller that had read "not paused"
    at the start of its request.

    ``paused``: ``True`` pauses, ``False`` computes without a pause (an explicit
    lift), and ``None`` -- the default -- keeps the pause in force under the row
    LOCK, which is the only reading of "don't change the pause" a concurrent
    operator cannot slip past. In force, not merely stored: a row written back
    beneath its transition log holds the decision from before the log's last
    move, and the log is what was recorded and published
    (:func:`assurance.revision.decision_in_force`). Reading the pause off such a
    row recorded, on the repair, a lift -- or a re-pause -- no operator made.
    """
    from . import observed_outcomes
    from .revision import accept_transition, decision_in_force

    with transaction.atomic():
        locked = Deployment.objects.select_for_update().get(pk=deployment.pk)
        # ONE reading of the decision in force, under the lock: the pause is taken
        # from it and the move is made from it, so the two cannot disagree, and a
        # row behind its log is repaired -- and reported -- once.
        in_force = decision_in_force(locked)
        hold_pause = in_force.decision == Deployment.Decision.PAUSED if paused is None else paused
        keyring = observed_outcomes.trusted_keyring()
        # ONE read of the keyring: the decision is computed under it and stamped
        # with it. Three reads (here, inside the composition, and in the
        # fingerprint) could each see a different file mid-rotation, and a READY
        # computed under the old keys was stamped as current under the new ones.
        # Read once, so the decision and the moment it stops holding come from the
        # same reading. A pause reads nothing, and nothing about it expires.
        parts = None if hold_pause else read_decision_parts(locked, keyring=keyring)
        decision = compute_decision(locked, paused=hold_pause, parts=parts, keyring=keyring)
        accept_transition(locked, to_decision=decision, in_force=in_force)
        Deployment.objects.filter(pk=locked.pk).update(
            decision_keyring=observed_outcomes.keyring_fingerprint(keyring),
            decision_valid_until=parts.accepted_risk["valid_until"] if parts is not None else None,
            decision_policy=_current_policy_pin(),
        )
    deployment.refresh_from_db(
        fields=["decision", "decision_revision", "decision_keyring", "decision_valid_until", "decision_policy"]
    )
    # Level with its transition log -- the move above was made from the log's
    # reading -- so publishing this instance next asks the log nothing.
    deployment.logged_revision = deployment.decision_revision
    return decision


def _current_policy_pin() -> str:
    """The pin of the rules in force (see Deployment.decision_policy). Imported
    here because assurance.policy reads this module's constants."""
    from .policy import policy_pin

    return policy_pin()


def refresh_stored_decisions(deployment_ids) -> None:
    """Recompute the stored decision of each deployment named, by pk.

    For writers that know which deployments they touched but hold no instance of
    them: the Django admin, and the after-commit backstop in
    :mod:`assurance.signals`. A deployment deleted since its input was written has
    no decision left to refresh and is skipped. Each keeps its operator's pause as
    it is in force under its LOCKED row, as every refresh does.
    """
    ids = {pk for pk in deployment_ids if pk is not None}
    if not ids:
        return
    from .latent import fire_due_conditions
    from .served_route import note_route_quietly

    # In pk order, so two writers refreshing the same pair of deployments take
    # their row locks in the same order rather than each holding the other's.
    for deployment in Deployment.objects.filter(pk__in=ids).order_by("pk"):
        # A declared latent condition the write made true fires first, so the
        # decision refreshed here reads the claim it marked STALE.
        fire_due_conditions(deployment)
        # And the route the write left serving is noted, so a run after it binds.
        note_route_quietly(deployment)
        recompute_decision(deployment)


def current_decision(deployment: Deployment) -> str | None:
    """The stored decision, reconciled first if it was computed under a different
    outcome keyring than the one in force -- or before the signed-outcome rule.

    For the surfaces that PUBLISH the stored decision (the receipt, the bundle, the
    incident pack). Every other input reaches the decision through a write that
    recomputes it; the keyring is a file, and a withdrawn key used to leave a
    stored READY behind that the receipt went on reporting. Only deployments with
    chain outcomes can move on a keyring change, so only they are reconciled.

    Before the keyring, the row is held to its own transition log
    (:func:`assurance.revision.hold_to_its_log`): a row behind its log is brought
    up to it through the one writer, and ``deployment`` holds the decision the log
    records even where the row cannot be written. A logged pause the stale row
    does not hold is published as the pause it is, never as the READY beneath it.
    Asking costs nothing for an instance read with the log head
    (:func:`assurance.revision.logged_head`), as the list and the bundle read
    theirs, and one query otherwise.

    The cost is paid by the first read after a rotation: one recompute, under the
    row lock, per stale deployment it publishes -- about twenty queries each -- and
    a read that meets a writer holding that lock waits for it. If the wait outlasts
    the database timeout the read fails rather than publish a decision computed
    under the withdrawn keys. The eager path is ``manage.py recompute_chain_decisions``,
    run when the keyring changes, after which every read is the two-query one."""
    from . import observed_outcomes
    from .revision import hold_to_its_log

    hold_to_its_log(deployment)
    # Time moves the decision where no write does: a risk accepted until a moment
    # that has now passed. The stored decision records when that happens, and the
    # first read after it recomputes -- rather than go on publishing the
    # READY_RESTRICTED an acceptance that no longer stands was holding up.
    valid_until = getattr(deployment, "decision_valid_until", None)
    if valid_until is not None and timezone.now() >= valid_until:
        recompute_decision(deployment)
        return deployment.decision
    # Rules move the decision where no write does too: a release that adds a cap
    # changes what the same stored inputs imply. A decision stamped under other
    # rules is recomputed rather than published under rules that no longer hold.
    # Any deployment: every rule is a rule of every decision. One with no stamp
    # predates it, and is the upgrade's: the post-migrate receiver recomputes
    # every such decision at the migrate that adds the column, keyed on the data,
    # so a migrate that stops part-way leaves them for the next -- and the code
    # that reads the stamp cannot run without that migrate.
    policy = getattr(deployment, "decision_policy", None)
    if policy is not None and policy != _current_policy_pin() and deployment.decision is not None:
        recompute_decision(deployment)
        return deployment.decision
    if deployment.decision_keyring == observed_outcomes.keyring_fingerprint():
        return deployment.decision
    # Stale or never stamped -- but only a deployment with chain outcomes can move
    # on a keyring change. A caller that already knows (the bundle annotates it in
    # its one query) saves the lookup.
    has_chains = getattr(deployment, "has_chain_outcomes", None)
    if has_chains is None:
        has_chains = deployment.chain_outcomes.exists()
    if has_chains:
        recompute_decision(deployment)
    return deployment.decision
