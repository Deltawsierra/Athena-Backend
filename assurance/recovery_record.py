"""SPINE's recovery record (SP-1): one per incident, its state derived from its witnesses.

The incident is a :class:`~assurance.models.Finding` (:mod:`assurance.incident`). Its
recovery record is its :class:`~assurance.models.RecoveryRecord` rows, oldest first: each
a ``mythos_core.status.Recovery`` -- one of the seven recovery states with the conditions
that support it -- and what it rests on. Nothing here is a vocabulary of its own: the
states, the steps that may follow each and the release words are ``mythos_core.status``;
the coverage manifest and the rule that a declared gap holds a pass back are
``mythos_core.coverage``.

**What a step rests on** (:func:`resolve`), each link resolved in the finding's own
deployment and refused when it is another's or does not verify now:

=====================  ===========================================  =====================
Link                   Read from                                    Witness of
=====================  ===========================================  =====================
the incident           the finding                                  ``incident_recorded``
evidence (posted)      ``Evidence`` of the deployment's findings    ``evidence_linked``
permits (posted)       a ``WorkflowChainOutcome`` that is a signed  ``effect_permitted``
                       Action Gate decision that permitted
receipts (posted)      an ``EffectReconciliationReceipt`` in force  ``effect_read_back``
                       whose gate decision is a linked permit       (committed) or a
                                                                    blocker (failed)
the repair contract    the finding's current ``RepairContract``     ``repair_agreed``
the closure evidence   the latest ``RetestClosureEvidence``, when   ``repair_tested``
                       the closure gate finds nothing to refuse
the owner's acceptance the deployment's owner, until a stated end   ``owner_accepted``
the decision           the deployment's latest ``DecisionTransition``  (a link, no witness)
=====================  ===========================================  =====================

A posted list that is left out is carried from the step before; one that is given
replaces it, and the history keeps what each step rested on.

**The state is derived** (:func:`derive`), never typed in. A state is supported when its
witnesses exist: ``contained_with_gaps`` an effect read back and declared gaps;
``repair_proposed`` a repair agreed; ``repair_tested`` that and a closure the gate would
allow; ``restored_with_restrictions`` that, an effect read back and declared restrictions;
``recovery_accepted`` a tested repair and the owner's acceptance; ``recovery_incomplete``
a blocker, which every other state but a reopen gives way to. Each new step is the
furthest supported state S1 lets follow the one before (``status.recovery_may_follow``,
checked again by ``status.check_recovery_step``); a step whose own support is gone and
that no other state can follow is reopened to ``under_investigation``, naming it. One
:func:`record` writes every step that is supported, one row each, from
``under_investigation`` on; one that moves nothing is refused.

**Coverage.** A declared gap, a source not fully observed, unknown inventory or no
required source at all (``coverage.coverage_ratio``) holds back both recovered states,
``restored_with_restrictions`` and ``recovery_accepted``: a gap never yields one. A step
held back that way names each gap among its ``gaps``, and its release is
``coverage.release_given_coverage(manifest, PASS)``: ``AUDIT_INCOMPLETE``. Otherwise the
release is ``PASS`` only for ``recovery_accepted`` (``status.release_may_pass``) and
``FAIL`` for every other state.

**Residual uncertainty** is a list of statements, each with its sources: every open
``Unknown`` of the finding, every coverage gap, every receipt that cannot say whether its
effect took, and any posted statement, whose sources must be this step's own links.

Reads and writes only this record; nothing a stop or the decision reads.
"""

from __future__ import annotations

import re
import uuid

from django.db import IntegrityError, transaction
from django.utils import timezone
from mythos_core import coverage as cov
from mythos_core import status as st

from . import composition, effect_reconciliation, observed_outcomes, retest_closure

INCIDENT_RECORDED = "incident_recorded"
EVIDENCE_LINKED = "evidence_linked"
EFFECT_PERMITTED = "effect_permitted"
EFFECT_READ_BACK = "effect_read_back"
EFFECT_NOT_APPLIED = "effect_not_applied"
REPAIR_AGREED = "repair_agreed"
REPAIR_TESTED = "repair_tested"
OWNER_ACCEPTED = "owner_accepted"

#: The conditions every step names, and those each state rests on besides.
_BASE = (INCIDENT_RECORDED, EVIDENCE_LINKED, EFFECT_PERMITTED)
_NEEDS = {
    st.UNDER_INVESTIGATION: (),
    st.CONTAINED_WITH_GAPS: (EFFECT_READ_BACK,),
    st.REPAIR_PROPOSED: (REPAIR_AGREED,),
    st.REPAIR_TESTED: (REPAIR_AGREED, REPAIR_TESTED),
    st.RESTORED_WITH_RESTRICTIONS: (REPAIR_AGREED, REPAIR_TESTED, EFFECT_READ_BACK),
    st.RECOVERY_ACCEPTED: (REPAIR_AGREED, REPAIR_TESTED, OWNER_ACCEPTED),
    st.RECOVERY_INCOMPLETE: (EFFECT_NOT_APPLIED,),
}
#: How far along each state is. ``recovery_incomplete`` has no rank: its blockers come first.
_RANK = {state: rank for rank, state in enumerate(st.RECOVERY_STATES[:6])}
#: The recovered states: neither is ever reached on incomplete coverage.
RECOVERED = frozenset({st.RESTORED_WITH_RESTRICTIONS, st.RECOVERY_ACCEPTED})

POSTED = ("evidence", "permits", "receipts", "coverage", "gaps", "restrictions", "residual_uncertainty")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")
_MOST = 100


class RecoveryRefused(ValueError):
    """A recovery step refused, with the code of the rule it broke."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _list(value, what: str, pattern=None, longest: int = 200) -> list[str]:
    if not isinstance(value, list) or len(value) > _MOST:
        raise RecoveryRefused("malformed", f"{what} is a list of at most {_MOST}")
    for item in value:
        if type(item) is not str or not item.strip() or len(item) > longest:
            raise RecoveryRefused("malformed", f"each of {what} is a non-empty string of at most {longest}")
        if pattern is not None and not pattern.fullmatch(item):
            raise RecoveryRefused("malformed", f"each of {what} is an identifier")
    if len(set(value)) != len(value):
        raise RecoveryRefused("malformed", f"{what} names each one once")
    return list(value)


def _scope(finding) -> str:
    return f"finding:{finding.uuid}"


def manifest_of(finding, data) -> cov.Manifest:
    """The step's coverage manifest, scoped to its incident: ``{"sources": [{source, kind,
    start, end}], "observations": [{source, start, end, basis}], "gaps": [{kind, subject,
    start?, end?, detail?}]}``. None of it given is a manifest that declares no source."""
    data = {} if data is None else data
    if not isinstance(data, dict) or set(data) - {"sources", "observations", "gaps"}:
        raise RecoveryRefused("malformed", "coverage holds sources, observations and gaps, and nothing else")
    try:
        return cov.Manifest(
            scope=_scope(finding),
            sources=[cov.RequiredSource(s["source"], s["kind"], cov.Interval(s["start"], s["end"])) for s in data.get("sources", [])],
            observations=[
                cov.Observation(o["source"], cov.Interval(o["start"], o["end"]), o["basis"])
                for o in data.get("observations", [])
            ],
            gaps=[
                cov.Gap(g["kind"], g["subject"], cov.Interval(g["start"], g["end"]) if "start" in g else None, g.get("detail", ""))
                for g in data.get("gaps", [])
            ],
        )
    except cov.CoverageError as exc:
        raise RecoveryRefused(f"coverage_{exc.code}", str(exc)) from None
    except (KeyError, TypeError, AttributeError):
        raise RecoveryRefused("malformed", "coverage: a source, observation or gap is missing a field") from None


def _manifest_json(manifest: cov.Manifest) -> dict:
    def span(interval):
        return {} if interval is None else {"start": interval.start, "end": interval.end}

    return {
        "sources": [{"source": s.source, "kind": s.kind, **span(s.interval)} for s in manifest.sources],
        "observations": [{"source": o.source, **span(o.interval), "basis": o.basis} for o in manifest.observations],
        "gaps": [{"kind": g.kind, "subject": g.subject, **span(g.interval), "detail": g.detail} for g in manifest.gaps],
    }


def _coverage_holds(manifest: cov.Manifest) -> tuple[list[str], bool]:
    """Each thing that holds a recovered state back, named, and whether coverage is complete."""
    measured = cov.coverage_ratio(manifest)
    holds = [f"coverage:{gap.kind}:{gap.subject}" for gap in measured.gaps]
    holds += [f"coverage:missing:{source}" for source, left in measured.missing.items() if left]
    holds += [f"coverage:unknown_inventory:{source}" for source in measured.undeclared]
    if measured.denominator == 0:
        holds.append("coverage:no_required_source")
    return list(dict.fromkeys(holds)), measured.complete


# ------------------------------------------------------------------ the links


def resolve(finding, body=None, previous=None) -> tuple[dict, dict]:
    """``(links, coverage)`` for a step of ``finding``'s recovery: what ``body`` posts,
    with what it leaves out carried from ``previous``, each resolved in the finding's own
    deployment. Refuses a link that is another deployment's, or does not verify now."""
    from .models import (
        DecisionTransition,
        EffectReconciliationReceipt,
        Evidence,
        RepairContract,
        Unknown,
        WorkflowChainOutcome,
    )

    body = {} if body is None else body
    if not isinstance(body, dict):
        raise RecoveryRefused("malformed", "a recovery step is posted as an object")
    extra = sorted(str(key) for key in body if key not in POSTED)
    if extra:
        raise RecoveryRefused(
            "not_posted",
            f"{extra}: not what a recovery step takes. Its state, conditions, release and the gaps its "
            "coverage holds are derived from what it rests on, never posted",
        )
    before = previous.links if previous is not None else {}
    carried = {
        "evidence": [e["uuid"] for e in before.get("evidence", [])],
        "permits": [p["outcome_id"] for p in before.get("permits", [])],
        "receipts": [r["receipt_id"] for r in before.get("receipts", [])],
        "gaps": before.get("gaps", []),
        "restrictions": before.get("restrictions", []),
        "residual_uncertainty": before.get("uncertainty", []),
    }
    given = {**carried, **{key: value for key, value in body.items() if key != "coverage"}}
    deployment = finding.deployment
    keyring = observed_outcomes.trusted_keyring()

    evidence_ids = [str(uuid.UUID(i)) for i in _list(given["evidence"], "evidence", _UUID)]
    found = {
        str(e.uuid): e
        for e in Evidence.objects.filter(uuid__in=evidence_ids, finding__deployment_id=deployment.pk).only(
            "uuid", "classification"
        )
    }
    evidence = []
    for one in evidence_ids:
        if one not in found:
            raise RecoveryRefused("unknown_link", f"evidence {one} is not evidence of this deployment")
        evidence.append({"uuid": one, "classification": found[one].classification})

    permit_ids = _list(given["permits"], "permits", _ID)
    outcomes = {
        o.outcome_id: o for o in WorkflowChainOutcome.objects.filter(deployment_id=deployment.pk, outcome_id__in=permit_ids)
    }
    permits = []
    for one in permit_ids:
        outcome = outcomes.get(one)
        if outcome is None:
            raise RecoveryRefused("unknown_link", f"permit {one} is not a gate decision of this deployment")
        basis = observed_outcomes.basis_in_force(outcome, keyring, deployment_uuid=str(deployment.uuid))
        kind = composition.evidence_kind(basis, outcome.observer_engine)
        if kind != composition.EVIDENCE_AUTHORIZATION_CHECK or outcome.status != composition.HELD:
            raise RecoveryRefused(
                "not_a_permit", f"permit {one} is not a signed Action Gate decision that permitted, verified now"
            )
        permits.append({"outcome_id": one, "workflow": outcome.workflow})

    receipt_ids = _list(given["receipts"], "receipts", _ID)
    rows = {
        r.receipt_id: r
        for r in EffectReconciliationReceipt.objects.filter(deployment_id=deployment.pk, receipt_id__in=receipt_ids)
    }
    receipts = []
    for one in receipt_ids:
        row = rows.get(one)
        if row is None:
            raise RecoveryRefused("unknown_link", f"receipt {one} is not a reconciliation receipt of this deployment")
        if effect_reconciliation.in_force(row, keyring) is None:
            raise RecoveryRefused("not_in_force", f"receipt {one} does not verify now")
        if row.gate_outcome_id not in permit_ids:
            raise RecoveryRefused(
                "unpermitted_receipt", f"receipt {one} reads back gate decision {row.gate_outcome_id}, not a linked permit"
            )
        receipts.append(
            {"receipt_id": one, "dispatch_id": row.dispatch_id, "gate_outcome_id": row.gate_outcome_id,
             "conclusion": row.conclusion}
        )

    contract = RepairContract.objects.filter(finding_id=finding.pk).order_by("-version").first()
    closure = retest_closure.latest_record(finding)
    unknowns = [
        {"uuid": str(u.uuid), "question": u.question}
        for u in Unknown.objects.filter(
            deployment_id=deployment.pk, finding_id=finding.pk,
            status__in=(Unknown.Status.OPEN, Unknown.Status.INVESTIGATING),
        ).order_by("id")
    ]
    sources = {
        *(("evidence", e["uuid"]) for e in evidence), *(("permit", p["outcome_id"]) for p in permits),
        *(("receipt", r["receipt_id"]) for r in receipts), *(("unknown", u["uuid"]) for u in unknowns),
    }
    links = {
        "incident": str(finding.uuid),
        "evidence": evidence,
        "permits": permits,
        "receipts": receipts,
        "decision": DecisionTransition.objects.filter(deployment_id=deployment.pk)
        .order_by("-revision").values("revision", "to_decision", "basis_digest").first(),
        "repair_contract": None if contract is None else {
            "uuid": str(contract.uuid), "version": contract.version, "content_digest": contract.content_digest,
        },
        "closure_evidence": None if closure is None else {
            "uuid": str(closure.uuid), "carries_closure": not retest_closure.refusal_reasons(finding),
        },
        "unknowns": unknowns,
        "gaps": _list(given["gaps"], "gaps"),
        "restrictions": _list(given["restrictions"], "restrictions"),
        "uncertainty": _uncertainty(given["residual_uncertainty"], sources),
    }
    data = body["coverage"] if "coverage" in body else (previous.coverage if previous is not None else None)
    return links, _manifest_json(manifest_of(finding, data))


def _uncertainty(value, sources: set) -> list[dict]:
    """Posted residual uncertainty: each statement with at least one source, every source
    one of this step's own links (its evidence, permits, receipts, the finding's unknowns)."""
    if not isinstance(value, list) or len(value) > _MOST:
        raise RecoveryRefused("malformed", f"residual_uncertainty is a list of at most {_MOST}")
    kept = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"statement", "sources"}:
            raise RecoveryRefused("malformed", "each residual uncertainty is {statement, sources}")
        statement, named = item["statement"], item["sources"]
        if type(statement) is not str or not statement.strip() or len(statement) > 500:
            raise RecoveryRefused("malformed", "a residual uncertainty states it, in at most 500 characters")
        if not isinstance(named, list) or not named:
            raise RecoveryRefused("unsourced_uncertainty", "a residual uncertainty names its sources")
        for source in named:
            if not isinstance(source, dict) or (source.get("kind"), source.get("ref")) not in sources or len(source) != 2:
                raise RecoveryRefused("unknown_source", "a residual uncertainty's source is one of this step's links")
        kept.append({"statement": statement, "sources": [{"kind": s["kind"], "ref": s["ref"]} for s in named]})
    return kept


# --------------------------------------------------------- the derivation


def _facts(links: dict, accepted: str) -> dict[str, list[tuple[str, str]]]:
    receipts = links["receipts"]
    contract, closure = links["repair_contract"], links["closure_evidence"]
    return {
        INCIDENT_RECORDED: [("finding", links["incident"])],
        EVIDENCE_LINKED: [("evidence", e["uuid"]) for e in links["evidence"]],
        EFFECT_PERMITTED: [("permit", p["outcome_id"]) for p in links["permits"]],
        EFFECT_READ_BACK: [("receipt", r["receipt_id"]) for r in receipts if r["conclusion"] == st.COMMITTED],
        EFFECT_NOT_APPLIED: [("receipt", r["receipt_id"]) for r in receipts if r["conclusion"] == st.FAILED],
        REPAIR_AGREED: [] if contract is None else [("repair_contract", contract["uuid"])],
        REPAIR_TESTED: [("closure_evidence", closure["uuid"])] if closure and closure["carries_closure"] else [],
        OWNER_ACCEPTED: [("owner", accepted)] if accepted else [],
    }


def _step(before, supported):
    """The state of the next step after one in ``before`` (None: there is none yet), or
    None when nothing may follow it that the witnesses support."""
    if before is None:
        return st.UNDER_INVESTIGATION
    after = [
        state for state in st.RECOVERY_STATES
        if state != st.UNDER_INVESTIGATION and st.recovery_may_follow(before, state) and supported(state)
    ]
    if st.RECOVERY_INCOMPLETE in after:
        return st.RECOVERY_INCOMPLETE
    floor = _RANK.get(before, -1) if supported(before) else -1
    best = max((state for state in after if _RANK.get(state, -1) > floor), key=_RANK.get, default=None)
    if best is None and not supported(before) and before not in st.RECOVERY_TERMINAL:
        return st.UNDER_INVESTIGATION
    return best


def _as_recovery(row) -> st.Recovery:
    return st.Recovery(
        ref=str(row.uuid),
        state=row.state,
        conditions=tuple(_condition_texts(row.conditions)),
        gaps=tuple(row.gaps),
        restrictions=tuple(row.restrictions),
        owner_acceptance=next((c["witness"]["ref"] for c in row.conditions if c["condition"] == OWNER_ACCEPTED), ""),
        reopens=row.reopens,
    )


def _condition_texts(conditions: list[dict]) -> list[str]:
    return [f"{c['condition']}:{c['witness']['kind']}:{c['witness']['ref']}" for c in conditions]


def derive(*, ref: str, links: dict, manifest: cov.Manifest, accepted: str, previous) -> dict | None:
    """What a step resting on ``links``, ``manifest`` and ``accepted`` (the owner's
    acceptance in force, or blank) says after ``previous``: its state, reopens,
    conditions, gaps, restrictions, release and residual uncertainty -- or None, when
    nothing may follow ``previous`` that the witnesses support. Pure."""
    facts = _facts(links, accepted)
    holds, complete = _coverage_holds(manifest)
    blocked = bool(facts[EFFECT_NOT_APPLIED])

    def supported(state, *, coverage_counts=True):
        if state == st.RECOVERY_INCOMPLETE:
            return blocked
        if blocked and state != st.UNDER_INVESTIGATION:
            return False
        if not all(facts[condition] for condition in _NEEDS[state]):
            return False
        if (state == st.CONTAINED_WITH_GAPS and not links["gaps"]) or (
            state == st.RESTORED_WITH_RESTRICTIONS and not links["restrictions"]
        ):
            return False
        return complete or state not in RECOVERED or not coverage_counts

    state = _step(None if previous is None else previous.state, supported)
    if state is None:
        return None
    held = not complete and any(supported(one, coverage_counts=False) for one in RECOVERED)
    conditions = [
        {"condition": name, "witness": {"kind": kind, "ref": witness}}
        for name in dict.fromkeys((*_BASE, *_NEEDS[state]))
        for kind, witness in facts[name]
    ]
    gaps = [*links["gaps"], *(f"{EFFECT_NOT_APPLIED}:receipt:{r}" for _, r in facts[EFFECT_NOT_APPLIED])]
    gaps += holds if held else []
    reopens = str(previous.uuid) if previous is not None and state == st.UNDER_INVESTIGATION else ""
    try:
        recovery = st.Recovery(
            ref=ref, state=state, conditions=tuple(_condition_texts(conditions)), gaps=tuple(gaps),
            restrictions=tuple(links["restrictions"]),
            owner_acceptance=accepted if state == st.RECOVERY_ACCEPTED else "", reopens=reopens,
        )
        if previous is not None:
            st.check_recovery_step(_as_recovery(previous), recovery)
    except st.RecoveryError as exc:
        raise RecoveryRefused(exc.code, str(exc)) from None
    gate = st.PASS if st.release_may_pass([recovery]) or held else st.FAIL
    residual = [
        *({"statement": u["question"], "sources": [{"kind": "unknown", "ref": u["uuid"]}]} for u in links["unknowns"]),
        *({"statement": hold, "sources": [{"kind": "coverage", "ref": manifest.scope}]} for hold in holds),
        *(
            {"statement": "effect_unknown", "sources": [{"kind": "receipt", "ref": r["receipt_id"]}]}
            for r in links["receipts"] if r["conclusion"] == st.UNKNOWN
        ),
        *links["uncertainty"],
    ]
    return {
        "state": state,
        "reopens": reopens,
        "conditions": conditions,
        "gaps": gaps,
        "restrictions": list(links["restrictions"]),
        "release": cov.release_given_coverage(manifest, gate),
        "residual_uncertainty": residual,
    }


def _derived(row, previous) -> dict | None:
    in_force = row.accepted_by_id is not None and row.accepted_until is not None and row.accepted_until > row.recorded_at
    return derive(
        ref=str(row.uuid), links=row.links, manifest=manifest_of(row.finding, row.coverage),
        accepted=f"user:{row.accepted_by_id}" if in_force else "", previous=previous,
    )


def _stored(row) -> dict:
    return {
        "state": row.state, "reopens": row.reopens, "conditions": row.conditions, "gaps": row.gaps,
        "restrictions": row.restrictions, "release": row.release, "residual_uncertainty": row.residual_uncertainty,
    }


def check_derived(row) -> None:
    """Refuse ``row`` (unsaved) unless every derived field is what :func:`derive` says of
    its own links, coverage and acceptance after the step before it."""
    from .models import RecoveryRecord

    previous = RecoveryRecord.objects.filter(finding_id=row.finding_id, version__lt=row.version).order_by("-version").first()
    try:
        derived = _derived(row, previous) if row.links.get("incident") == str(row.finding.uuid) else None
    except (KeyError, TypeError, AttributeError):
        derived = None
    if derived != _stored(row):
        raise RecoveryRefused(
            "not_derived",
            "a recovery step's state, conditions, gaps, restrictions, release and residual uncertainty are derived "
            "from what it rests on and the step before it; this one says otherwise",
        )


def draft(finding, *, version, links, coverage=None, accepted_by=None, accepted_until=None, recorded_by=None,
          recorded_at=None, previous=None):
    """The next step of ``finding``'s recovery after ``previous``, unsaved, with every
    derived field derived -- or None, when nothing may follow ``previous``."""
    from .models import RecoveryRecord

    row = RecoveryRecord(
        finding=finding, version=version, links=links, coverage=coverage or {}, accepted_by=accepted_by,
        accepted_until=accepted_until, recorded_by=recorded_by, recorded_at=recorded_at or timezone.now(),
    )
    derived = _derived(row, previous)
    if derived is None:
        return None
    row.state, row.reopens, row.conditions = derived["state"], derived["reopens"], derived["conditions"]
    row.gaps, row.restrictions, row.release = derived["gaps"], derived["restrictions"], derived["release"]
    row.residual_uncertainty = derived["residual_uncertainty"]
    return row


def record(finding, *, by=None, body=None, accept_until=None) -> list:
    """Record the steps of ``finding``'s recovery that what ``body`` links now supports,
    one row per step, and return them. ``accept_until`` is the owner's acceptance, given
    by ``by``, which must be the deployment's owner. Refused, with nothing recorded, when
    nothing moves or a link or the acceptance is refused."""
    from .models import RecoveryRecord

    now = timezone.now()
    previous = RecoveryRecord.objects.filter(finding_id=finding.pk).order_by("-version").first()
    if previous is not None and previous.state in st.RECOVERY_TERMINAL:
        raise RecoveryRefused("terminal", f"the recovery was accepted (step {previous.version}); nothing follows")
    if accept_until is not None:
        if finding.deployment.owner_id is None:
            raise RecoveryRefused("no_owner", "no owner set for this deployment")
        if by is None or by.pk != finding.deployment.owner_id:
            raise RecoveryRefused("not_the_owner", "only the deployment's owner accepts its recovery")
        if accept_until <= now:
            raise RecoveryRefused("acceptance_ended", "an acceptance names an end in the future")
    links, coverage = resolve(finding, body, previous)
    steps = []
    try:
        with transaction.atomic():
            for _ in range(len(st.RECOVERY_STATES) + 1):
                row = draft(
                    finding, version=1 if previous is None else previous.version + 1, links=links, coverage=coverage,
                    accepted_by=by if accept_until is not None else None, accepted_until=accept_until,
                    recorded_by=by, recorded_at=now, previous=previous,
                )
                if row is None:
                    break
                row.save()
                steps.append(row)
                previous = row
    except IntegrityError:
        raise RecoveryRefused("raced", "another step of this recovery was recorded at the same time") from None
    if not steps:
        raise RecoveryRefused(
            "nothing_moved",
            f"nothing moved: what this step rests on supports no state that may follow {previous.state!r}",
        )
    return steps


# ------------------------------------------------------------------ the reads


def served(row) -> dict:
    """One step as its reads serve it: every derived field as recorded, what it rests
    on, its coverage manifest with what ``coverage.coverage_ratio`` measures of it, and
    who accepted and recorded it (``None`` when nobody is on record). No summary badge:
    the state is one of S1's words, beside its conditions and gaps."""
    measured = cov.coverage_ratio(manifest_of(row.finding, row.coverage))
    return {
        "ref": str(row.uuid),
        "version": row.version,
        "state": row.state,
        "reopens": row.reopens or None,
        "conditions": row.conditions,
        "gaps": row.gaps,
        "restrictions": row.restrictions,
        "release": row.release,
        "residual_uncertainty": row.residual_uncertainty,
        "links": row.links,
        "coverage": {
            "manifest": row.coverage,
            "observed_sources": measured.numerator,
            "required_sources": measured.denominator,
            "complete": measured.complete,
            "missing": {
                source: [{"start": i.start, "end": i.end} for i in left] for source, left in measured.missing.items() if left
            },
            "unknown_inventory": list(measured.unknown_inventory),
        },
        "accepted_by": row.accepted_by.username if row.accepted_by_id else None,
        "accepted_until": row.accepted_until.isoformat() if row.accepted_until else None,
        "recorded_by": row.recorded_by.username if row.recorded_by_id else None,
        "recorded_at": row.recorded_at.isoformat(),
    }


def _steps_of(finding_ids) -> dict:
    from .models import RecoveryRecord

    rows = (
        RecoveryRecord.objects.filter(finding_id__in=finding_ids)
        .select_related("finding", "accepted_by", "recorded_by")
        .order_by("finding_id", "version")
    )
    steps: dict = {}
    for row in rows:
        steps.setdefault(row.finding_id, []).append(row)
    return steps


def _incident(finding, steps: list) -> dict:
    last = steps[-1] if steps else None
    return {
        "finding": str(finding.uuid),
        "title": finding.title,
        "severity": finding.severity,
        "current": None if last is None else {"version": last.version, "state": last.state, "release": last.release},
        "steps": [served(step) for step in steps],
    }


def finding_record(finding) -> dict:
    """One incident's recovery record: every step, oldest first. Two queries."""
    return {"deployment": str(finding.deployment.uuid), **_incident(finding, _steps_of([finding.pk]).get(finding.pk, []))}


def deployment_records(deployment, *, offset: int, page_size: int) -> dict:
    """The deployment's incidents -- its findings that have a recovery record -- one page
    of them, each with every step oldest first, and how many there are: the count and
    the page are of this deployment's incidents only. Three queries."""
    from django.db.models import Exists, OuterRef

    from .history_reads import _envelope, _page
    from .models import Finding, RecoveryRecord

    incidents = Finding.objects.filter(
        Exists(RecoveryRecord.objects.filter(finding_id=OuterRef("pk"))), deployment_id=deployment.pk
    ).order_by("id")
    page, total = _page(incidents, offset, page_size)
    steps = _steps_of([finding.pk for finding in page])
    return _envelope(deployment, "incidents", [_incident(f, steps.get(f.pk, [])) for f in page], total, offset, page_size)
