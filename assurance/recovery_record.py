"""SPINE's recovery record (SP-1): one per incident, its state derived from its witnesses.

The incident is a :class:`~assurance.models.Finding` (:mod:`assurance.incident`). Its
recovery record is its :class:`~assurance.models.RecoveryRecord` rows, oldest first: each
a ``mythos_core.status.Recovery`` -- one of the seven recovery states with the conditions
that support it -- and what it rests on. Nothing here is a vocabulary of its own: the
states, the steps that may follow each and the release words are ``mythos_core.status``;
the coverage manifest and the rule that a declared gap holds a pass back are
``mythos_core.coverage``.

**What a step rests on** (:func:`resolve`), each link resolved in the finding's own
deployment and refused when it is another's or does not verify now (an evidence link also
keeps the asset its finding is attached to, when that asset is the deployment's own):

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
held back that way names each gap among its ``gaps`` and the recovered state it is held
back from (``held_back_from``: the furthest one its witnesses support but for the holds).

**The release is the core's** (SPINE SP-4, ``mythos_core.recovery_receipt``, Mythos-Core#82):
``release_status(state, gap, held_back_from, acceptance_carries)``, the one rule a recovery
receipt is computed with, so the record and a receipt of it cannot disagree. ``PASS`` only
for ``recovery_accepted`` whose acceptance carries, with no gap; ``AUDIT_INCOMPLETE`` for an
accepted step with a gap or for any step held back; ``FAIL`` for every other. A gap holds a
pass back, whatever it is. Every read computes the release the same way, from what it
serves, and no rule of this module computes one.

**Who vouches for each witness** (``support``, the core's support entries). A permit and a
receipt are signed records: the engine whose key signed it, and the key's id
(``engine``, ``key_id``). Every other witness -- the finding, its evidence, the repair
contract, the closure evidence -- is vouched for by the named person who recorded the step
that linked it, with that step's time (``actor``, ``stated_at``): carried from the step
before when it linked the same record and named its person, else this step's recorder. A
coverage look that names an added scope item is vouched for by whoever posted the manifest.
The owner's acceptance is no support entry: it is the acceptance. A witness that nobody can
be named for is not a support: it is a gap, ``support:<condition>:<kind>:<ref>``, with what
would close it. A row recorded before SP-4 names no voucher, and every read reads each of
its witnesses as such a gap: what the core says an unknown voucher is.

**Names, not prose.** A posted restriction or gap is a name or a pointer in the core's
grammar (ASCII letters, digits and ``._:/+-``, at most 200): free text is refused
(``not_a_name``), and a statement with its sources belongs in ``residual_uncertainty``. A
posted gap spelled as one this record derives is refused (``not_posted``). A stored one
that is not a name (only a row from before SP-4 can hold one) is shown as it is and named
among the gaps by a pointer, ``unnamed:restriction:<i>`` or ``unnamed:gap:<i>``. Each
person is a reference, ``user:<id>`` (``recorded_by_ref``, ``accepted_by_ref``), kept beside
the account's key so it outlives the account's removal.

**An acceptance ends.** A step is accepted until ``accepted_until``. Every read compares the
reader's own instant with it, as it compares the incident's current scope with the step's:
an accepted step whose acceptance has ended by then is served at the last state before it
that was not a recovered one, held back from nothing, its release computed (``FAIL``), and
its standing is the core's word for it, ``acceptance_ended``. The row is history and is not
rewritten. Each step's ``standing`` is the core's word for how it stands now, decided in the
core's order: ``superseded`` (a later step is the latest), ``acceptance_ended``, ``unknown``
(the scope is behind the step), ``scope_moved`` (a revision since) or ``current``.

**Scope (SPINE SP-3).** Each step names the revision of the incident's scope it was
derived under (``scope_revision``; :mod:`assurance.incident_scope`), and a recovered state
holds only for that revision. The words below are ``mythos_core.scope``'s (Mythos-Core#80),
read from the core: the kinds of scope item, the scope holds, and the rule that a scope
revision reopens an accepted recovery:

- *No declared scope is unknown, never ok.* With no revision on record a step cannot reach
  a recovered state: it is held back as a coverage gap holds it, names
  ``scope:not_declared`` among its gaps and reads ``AUDIT_INCOMPLETE``.
- *A wider scope.* When a later revision adds an item, a recovered step taken before it
  no longer stands. Its row is history and is not rewritten; every read
  (:func:`served`) shows it as the last state before it that was not a recovered one,
  with the revision and each added item among its gaps
  (``scope:revision:<n>:added:<kind>:<ref>``) and release ``AUDIT_INCOMPLETE``, and keeps
  what the row recorded beside it. A row from before SP-3 names no revision and reads the
  same way, as ``scope:not_declared``.
- *An added item stays an open gap until a step recorded under that revision links
  something that names it* (:func:`scope_items`). An item counts when it is in the
  step's scope, a revision after the first added it, and it has been in scope ever since.
  Three kinds of link name one, and the step records which did (``scope_items``):

  ============  =========================================================================
  ``evidence``  ``Evidence`` of the deployment whose finding is attached to that asset
                (``Finding.asset``, kept on the link by :func:`resolve`): something was
                found there, and it is linked. No recency rule.
  ``permit``    a linked Action Gate permit of that workflow, resolved as every permit is.
  ``coverage``  the step's coverage manifest lists the asset (source ``asset:<uuid>``) as
                a required source and observes it in full, and the manifest was posted
                at or after the revision that added the asset, by the server's clock
                (kept on the links as ``coverage_recorded_at``). It says the asset was
                looked at and nothing was found; it never reads as found and fixed. A
                source that is missing, not fully observed or not declared, a manifest
                posted before the revision, or a time that cannot be read, covers nothing.
  ============  =========================================================================

  One item's link covers that item and no other. Until every such item is named, both
  recovered states are held back: the step names each uncovered item among its gaps and
  reads ``AUDIT_INCOMPLETE``.
- *A narrowing ends the hold for the item it removes, openly.* A hold for an added item
  stands only while the item is in the current scope and nothing names it. Once a later
  revision removes it, it is no longer a gap: a recovered step that was held back only by
  it stands again with no new step, and the read (``scope_removed``) and every step
  derived after (``scope_items.removed``) list it with both revision numbers, who
  removed it and why. A revision that only removes items takes no recovered state away.
  The first declared scope's items are not tied one by one; only items added later are.
- *After a recovered step that no longer stands*, a step is recorded only when it answers
  something of what took the state away, or a blocker stands: a failure is never left
  unrecorded. A step whose links name none of the items still open moves nothing
  (``nothing_moved``). A chain already reopened goes on by SP-1's own rules from the
  links it carries, and a hold a narrowing has ended no longer holds it back. The step that
  does move returns to ``under_investigation`` under the current revision and names the
  step it sets aside (``reopens``). After ``restored_with_restrictions`` that is S1's
  reopen, checked by S1. S1 lets nothing follow ``recovery_accepted``, not even a reopen:
  the rule "a scope revision reopens an accepted recovery" is the core's
  ``mythos_core.scope.check_scope_reopen``, and after an accepted step that rule is asked
  instead, with each scope hold that stands against the accepted step: the new step is
  ``under_investigation``, names the accepted one in ``reopens``, and at least one hold
  stands. S1's step check runs from the new step on.

**Residual uncertainty** is a list of statements, each with its sources: every open
``Unknown`` of the finding, every coverage gap, a scope that is not declared, every
receipt that cannot say whether its effect took, and any posted statement, whose sources
must be this step's own links.

Reads and writes only this record; nothing a stop or the decision reads.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from django.db import IntegrityError, transaction
from django.utils import timezone
from mythos_core import coverage as cov
from mythos_core import scope as core_scope
from mythos_core import status as st

from . import composition, effect_reconciliation, incident_scope, observed_outcomes, retest_closure

INCIDENT_RECORDED = "incident_recorded"
EVIDENCE_LINKED = "evidence_linked"
EFFECT_PERMITTED = "effect_permitted"
EFFECT_READ_BACK = "effect_read_back"
EFFECT_NOT_APPLIED = "effect_not_applied"
REPAIR_AGREED = "repair_agreed"
REPAIR_TESTED = "repair_tested"
OWNER_ACCEPTED = "owner_accepted"
#: The condition a link that names an item a scope revision added supports
#: (:func:`scope_items`' ``covered_by``): it is a witness too, and someone vouches for it.
SCOPE_ITEM_NAMED = "scope_item_named"

#: The first part of each gap this record derives and nobody posts: a witness nobody can be
#: named for, a stored value that is not a name, a coverage hold, a blocker. (The scope holds
#: are the core's spelling and are told apart by the core, ``core_scope.is_scope_hold``.)
SUPPORT, UNNAMED, COVERAGE_HOLD = "support", "unnamed", "coverage"
#: The kinds of witness an engine's key signs; every other kind is vouched for by a person.
SIGNED_KINDS = ("permit", "receipt")


def _receipt():
    """``mythos_core.recovery_receipt`` (Mythos-Core#82): the release rule, the standings,
    the words a reader prints for a support entry and for what would close a gap. Read at
    first use, never with this module, as :mod:`assurance.effect_reconciliation` reads the
    observed-effect record: the URL conf, which a stop's request may load first, loads
    nothing of a receipt. It is data and pure functions: no clock, file, key or network."""
    from mythos_core import recovery_receipt

    return recovery_receipt


def is_name(value) -> bool:
    """Whether ``value`` is a name or an opaque pointer in the core's one grammar (ASCII
    letters, digits and ``._:/+-``, at most 200, starting with a letter or a digit): what a
    receipt takes for a restriction, a gap, a reference. ``mythos_core.evidence_record``
    offers no public check for it, so this reads its pattern, as the core's own
    ``recovery_receipt``, ``provenance`` and ``measures`` do."""
    from mythos_core.evidence_record import _NAME

    return type(value) is str and _NAME.fullmatch(value) is not None


def instant(value) -> str | None:
    """``value`` (an aware datetime, or an ISO 8601 text with its offset, as the links keep
    one) in the core's one form, ``YYYY-MM-DDTHH:MM:SS.ffffffZ``; None when it cannot be
    read."""
    try:
        when = value if isinstance(value, datetime) else datetime.fromisoformat(value)
        if when.tzinfo is None:
            return None
        return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError, OverflowError):
        return None

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
#: The recovered states: neither is ever reached on incomplete coverage or with no declared
#: scope, and each holds only for the scope revision its step was derived under.
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


def _derives(gap: str) -> bool:
    """Whether ``gap`` is spelled as a gap this record derives: a scope hold (or anything
    the core's scope prefix begins), a witness nobody vouches for, a pointer to a value
    that is not a name, a coverage hold or a blocker."""
    family = gap.split(":", 1)[0]
    scope_prefix = core_scope.NOT_DECLARED.split(":", 1)[0]
    return core_scope.is_scope_hold(gap) or family in (scope_prefix, SUPPORT, UNNAMED, COVERAGE_HOLD, EFFECT_NOT_APPLIED)


def _named(value: list[str], what: str) -> list[str]:
    """``value``, the posted ``restrictions`` or ``gaps``, each a name or a pointer in the
    core's grammar (:func:`is_name`), refused with the core's code when one is free text.
    A posted gap spelled as one this record derives is refused too: it is derived, never
    posted. The refusal never repeats what it refused."""
    for item in value:
        if not is_name(item):
            raise RecoveryRefused(
                _receipt().NOT_A_NAME,
                f"each of {what} is a name or a pointer (ASCII letters, digits and ._:/+-, at most 200, starting "
                "with a letter or a digit), and one is free text: a statement with its sources is posted as "
                "residual_uncertainty",
            )
        if what == "gaps" and _derives(item):
            raise RecoveryRefused(
                "not_posted",
                "a gap spelled as one the record derives (a scope or coverage hold, a blocker, a witness nobody "
                "vouches for, a value that is not a name) is derived from what the step rests on, never posted",
            )
    return value


def _posted_or_carried(value, what: str, *, posted: bool) -> list[str]:
    return _named(_list(value, what), what) if posted else _list(value, what)


def person_ref(user_id) -> str:
    """The reference a person is named by on this record, ``user:<id>``; ``""`` for nobody
    (:func:`assurance.incident_scope.person_ref`, the one spelling)."""
    return incident_scope.person_ref(user_id)


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


def resolve(finding, body=None, previous=None, now=None, by=None) -> tuple[dict, dict]:
    """``(links, coverage)`` for a step of ``finding``'s recovery recorded by ``by``: what
    ``body`` posts, with what it leaves out carried from ``previous``, each resolved in the
    finding's own deployment. Refuses a link that is another deployment's, or does not
    verify now, and a posted restriction or gap that is not a name (:func:`_named`).

    Each permit and receipt keeps the engine whose key signed it and the key's id, as they
    verified now; the coverage manifest keeps when and by whom it was posted."""
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
        str(e["uuid"]): e
        for e in Evidence.objects.filter(uuid__in=evidence_ids, finding__deployment_id=deployment.pk).values(
            "uuid", "classification", "finding__asset__uuid", "finding__asset__deployment_id"
        )
    }
    evidence = []
    for one in evidence_ids:
        if one not in found:
            raise RecoveryRefused("unknown_link", f"evidence {one} is not evidence of this deployment")
        # What the evidence names: the asset its finding is attached to, when that asset
        # is this deployment's own. None when the finding is attached to none.
        names = found[one]["finding__asset__uuid"] if found[one]["finding__asset__deployment_id"] == deployment.pk else None
        evidence.append(
            {"uuid": one, "classification": found[one]["classification"], "asset": None if names is None else str(names)}
        )

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
        # Who vouches for it: the engine the signed outcome is bound to, and its key.
        permits.append(
            {"outcome_id": one, "workflow": outcome.workflow, "engine": outcome.observer_engine or None,
             "key_id": outcome.observer_key_id or None}
        )

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
        # Who vouches for it: the key it verified under now, and that key's engine.
        signer = keyring.get(row.observer_key_id) if hasattr(keyring, "get") else None
        receipts.append(
            {"receipt_id": one, "dispatch_id": row.dispatch_id, "gate_outcome_id": row.gate_outcome_id,
             "conclusion": row.conclusion, "engine": getattr(signer, "engine", None) or None,
             "key_id": row.observer_key_id or None}
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
        # A posted list is names (_named); one carried from the step before is kept as it
        # was recorded, and a value in it that is not a name is named by a pointer.
        "gaps": _posted_or_carried(given["gaps"], "gaps", posted="gaps" in body),
        "restrictions": _posted_or_carried(given["restrictions"], "restrictions", posted="restrictions" in body),
        "uncertainty": _uncertainty(given["residual_uncertainty"], sources),
        # When the step's coverage manifest was posted, by the server's clock, and by whom:
        # now and this step's recorder for one posted with this step, as carried for one
        # carried from the step before.
        "coverage_recorded_at": (now or timezone.now()).isoformat() if "coverage" in body else before.get(
            "coverage_recorded_at"
        ),
        "coverage_recorded_by": person_ref(getattr(by, "pk", None)) if "coverage" in body else before.get(
            "coverage_recorded_by"
        ),
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


#: The kinds of link that name a scope item: SP-1's own witness kinds.
EVIDENCE, PERMIT, COVERAGE = "evidence", "permit", "coverage"


def _at_or_after(stamp, instant) -> bool:
    """Whether ``stamp`` (an ISO instant kept on the links) is at or after ``instant``.
    False when either cannot be read."""
    try:
        return datetime.fromisoformat(stamp) >= instant
    except (TypeError, ValueError):
        return False


def scope_items(links: dict, manifest: cov.Manifest, scope_revision, revisions) -> dict:
    """What a step derived under ``scope_revision`` and resting on ``links`` and
    ``manifest`` says of the items its scope gained and lost:

    - ``added``: each item of its scope that a revision after the first added and that
      has been in scope ever since, with the links that name it (``covered_by``, each
      ``{kind, ref}``): ``evidence`` of a finding attached to that asset; a ``permit`` of
      that workflow; ``coverage`` -- the manifest lists the asset as a required source,
      observes it in full, and was posted at or after the revision that added it. None
      named is an open gap.
    - ``removed``: each item a revision added and a later one removed, with both revision
      numbers, who removed it and why. Disclosed; not a gap.

    Both are None, never an empty list, where they cannot be established: no scope was
    declared, the step names a revision that is not among them, or a revision up to its
    own cannot be read. An empty list says that nothing was added, or nothing removed,
    and that is said only of a scope that was read. A readable scope that holds nothing
    now gained nothing and still lists what it lost.

    Pure."""
    declared = scope_revision is not None and scope_revision in {row.revision for row in revisions}
    standing = incident_scope.since(revisions, scope_revision) if declared else None
    if standing is None:
        return {"added": None, "removed": None}
    first = revisions[0].revision
    declared_at = {row.revision: getattr(row, "declared_at", None) for row in revisions}
    missing = cov.coverage_ratio(manifest).missing
    added = []
    for (kind, ref), revision in standing.items():
        if revision <= first:
            continue
        by = []
        if kind == core_scope.ASSET:
            by += [
                {"kind": EVIDENCE, "ref": one["uuid"]}
                for one in links.get("evidence", []) if isinstance(one, dict) and one.get("asset") == ref
            ]
            source = f"{kind}:{ref}"
            if missing.get(source) == () and _at_or_after(links.get("coverage_recorded_at"), declared_at[revision]):
                by.append({"kind": COVERAGE, "ref": source})
        elif kind == core_scope.WORKFLOW:
            by += [
                {"kind": PERMIT, "ref": one["outcome_id"]}
                for one in links.get("permits", []) if isinstance(one, dict) and one.get("workflow") == ref
            ]
        added.append({"revision": revision, "kind": kind, "ref": ref, "covered_by": by})
    return {"added": added, "removed": incident_scope.removed(revisions, scope_revision)}


def scope_holds_of(scope_revision, revisions, links: dict, manifest: cov.Manifest) -> list[str]:
    """Each thing about the incident's scope that holds a recovered state back for a step
    derived under ``scope_revision`` and resting on ``links`` and ``manifest``, named: no
    declared scope, an unreadable one, and each item its own scope gained that nothing
    it links names. Where what the scope gained cannot be established, the first two
    name it. Pure."""
    # Each hold once: one the core cannot name reads ``scope:unreadable`` from both.
    return list(dict.fromkeys((
        *incident_scope.holds(scope_revision, revisions),
        *(
            incident_scope.gap(item["revision"], item["kind"], item["ref"])
            for item in scope_items(links, manifest, scope_revision, revisions)["added"] or () if not item["covered_by"]
        ),
    )))


def lapsed(row, revisions) -> list[str]:
    """Each thing about the incident's scope that takes ``row``'s recovered state away,
    named (:func:`scope_holds_of`): empty when ``row`` is not a recovered state, or the
    scope revision it was derived under is current. Pure."""
    if row.state not in RECOVERED:
        return []
    return scope_holds_of(row.scope_revision, revisions, row.links, manifest_of(row.finding, row.coverage))


# ------------------------------------------------- who vouches, names, the release


def _witnesses(conditions, items) -> list[tuple[str, str, str]]:
    """Every ``(condition, kind, ref)`` a step rests on that someone must vouch for, each
    once: each condition's witness but the owner's acceptance (which is the acceptance, not
    a support), and each link that names an item the scope gained (``scope_item_named``)."""
    named = [
        (SCOPE_ITEM_NAMED, link.get("kind"), link.get("ref"))
        for item in ((items or {}).get("added") or ()) if isinstance(item, dict)
        for link in (item.get("covered_by") or ()) if isinstance(link, dict)
    ]
    return list(dict.fromkeys((
        *(
            (c["condition"], c["witness"]["kind"], c["witness"]["ref"])
            for c in conditions if c["condition"] != OWNER_ACCEPTED
        ),
        *named,
    )))


def _support_gap(condition, kind, ref) -> str:
    """The gap a witness nobody can be named for leaves."""
    return f"{SUPPORT}:{condition}:{kind}:{ref}"


def _entry(condition, kind, ref, voucher: dict) -> dict | None:
    """One support entry in the core's shape, or None when the core would not take it as
    one (it refuses an entry whose voucher is a placeholder, a word of reassurance, a key
    id it cannot read or an instant it cannot read): such a witness is a gap."""
    core = _receipt()
    entry = {"condition": condition, "kind": kind, "ref": ref, **voucher}
    try:
        core.support_sentence(entry)
    except core.RecoveryReceiptError:
        return None
    return entry


def support_of(conditions, links: dict, items, *, recorded_by: str, recorded_at, previous) -> tuple[list, list]:
    """``(support, gaps)``: who vouches for each witness of a step (:func:`_witnesses`),
    each in the core's support-entry shape and in its one order, and the gap each witness
    nobody can be named for leaves.

    - A permit or a receipt: the engine whose key signed it and the key's id, as the link
      keeps them (:func:`resolve`).
    - A coverage look that names an added item: whoever posted the manifest, when.
    - Every other witness: the named person who recorded the step that linked it, with
      that step's time -- carried from ``previous`` when it linked the same record and
      named its person, else ``recorded_by`` (``user:<id>``, blank for nobody) at
      ``recorded_at``.

    Pure."""
    carried = {}
    for entry in getattr(previous, "support", None) or ():
        if isinstance(entry, dict) and _receipt().ACTOR in entry and type(entry.get("kind")) is type(entry.get("ref")) is str:
            carried.setdefault((entry["kind"], entry["ref"]), entry)
    signed = {
        **{("permit", p.get("outcome_id")): p for p in links.get("permits", ()) if isinstance(p, dict)},
        **{("receipt", r.get("receipt_id")): r for r in links.get("receipts", ()) if isinstance(r, dict)},
    }
    actor, engine = _receipt().ACTOR, _receipt().ENGINE
    support, gaps = [], []
    for condition, kind, ref in _witnesses(conditions, items):
        if kind in SIGNED_KINDS:
            link = signed.get((kind, ref)) or {}
            voucher = {engine: link.get("engine"), "key_id": link.get("key_id")} if link.get("engine") else None
        elif kind == COVERAGE:
            by, at = links.get("coverage_recorded_by"), instant(links.get("coverage_recorded_at"))
            voucher = {actor: by, "stated_at": at} if by and at else None
        elif (kind, ref) in carried:
            voucher = {actor: carried[(kind, ref)][actor], "stated_at": carried[(kind, ref)].get("stated_at")}
        else:
            at = instant(recorded_at)
            voucher = {actor: recorded_by, "stated_at": at} if recorded_by and at else None
        entry = None if voucher is None else _entry(condition, kind, ref, voucher)
        if entry is None:
            gaps.append(_support_gap(condition, kind, ref))
        else:
            support.append(entry)
    support.sort(key=lambda e: (e["condition"], e["kind"], e["ref"]))
    return support, gaps


def unnamed(gaps, restrictions) -> list[str]:
    """A pointer for each of ``gaps`` and ``restrictions`` that is not a name
    (:func:`is_name`): ``unnamed:gap:<i>``, ``unnamed:restriction:<i>``, ``i`` its place in
    its list. Free text stays as it was recorded; the pointer is how a receipt can name it.
    A pointer is itself a name, so asking again of a list that holds one adds nothing."""
    return [
        *(f"{UNNAMED}:gap:{i}" for i, gap in enumerate(gaps) if not is_name(gap)),
        *(f"{UNNAMED}:restriction:{i}" for i, one in enumerate(restrictions) if not is_name(one)),
    ]


def _added_kind(gap: str) -> str | None:
    """The kind of item an added-item scope hold names, read back through the core's own
    spelling (``core_scope.gap``); None for any other gap."""
    parts = gap.split(":", 5)
    try:
        return parts[4] if len(parts) == 6 and core_scope.gap(int(parts[2]), parts[4], parts[5]) == gap else None
    except (core_scope.ScopeError, ValueError):
        return None


def would_close(gap: str) -> list[dict]:
    """What would close ``gap``: each kind of record, and whether an engine must sign it or
    a named person state it (``voucher``), with the words every reader prints for that
    (``voucher_words``, the core's). Never empty."""
    core = _receipt()
    engine, actor = core.ENGINE, core.ACTOR
    family = gap.split(":", 1)[0]
    if gap in (core_scope.NOT_DECLARED, core_scope.UNREADABLE):
        closers = [("scope_revision", actor)]
    elif core_scope.is_scope_hold(gap):
        kind = _added_kind(gap)
        closers = {
            core_scope.ASSET: [(COVERAGE, actor), (EVIDENCE, actor)],
            core_scope.WORKFLOW: [(PERMIT, engine)],
        }.get(kind, [("scope_revision", actor)])
    elif family == COVERAGE_HOLD:
        closers = [(COVERAGE, actor)]
    elif family == EFFECT_NOT_APPLIED:
        closers = [("receipt", engine)]
    elif family == SUPPORT and len(gap.split(":")) >= 4:
        kind = gap.split(":")[2]
        closers = [(kind, engine if kind in SIGNED_KINDS else actor)]
    else:
        # A posted gap, or a pointer to a value that is not a name: a later step, recorded
        # by a named person, that no longer lists it or names it.
        closers = [("recovery_step", actor)]
    return [{"kind": kind, "voucher": voucher, "voucher_words": core.voucher_words(voucher)} for kind, voucher in closers]


def release_of(*, state, gaps, held_back_from, acceptance_carries) -> str:
    """The release a step yields: the core's one rule
    (``mythos_core.recovery_receipt.release_status``), never one of this module's. A gap
    holds a pass back. Raises :class:`RecoveryRefused` with the core's code when the core
    refuses the four inputs."""
    core = _receipt()
    try:
        return core.release_status(
            state=state, gap=bool(gaps), held_back_from=held_back_from or None,
            acceptance_carries=bool(acceptance_carries),
        )
    except core.RecoveryReceiptError as exc:
        raise RecoveryRefused(exc.code, str(exc)) from None


def derive(
    *, ref: str, links: dict, manifest: cov.Manifest, accepted: str, previous, scope_revision=None, revisions=(),
    recorded_by: str = "", recorded_at=None,
) -> dict | None:
    """What a step resting on ``links``, ``manifest`` and ``accepted`` (the owner's
    acceptance in force, or blank), recorded by ``recorded_by`` (``user:<id>``, blank for
    nobody) at ``recorded_at``, says after ``previous``, derived under revision
    ``scope_revision`` of the incident's scope (None: none is declared) with every
    revision in ``revisions``, oldest first: its state, reopens, conditions, gaps,
    restrictions, release, what it is held back from, who vouches for each witness and
    its residual uncertainty -- or None, when nothing may follow ``previous`` that the
    witnesses support. Pure."""
    facts = _facts(links, accepted)
    holds, complete = _coverage_holds(manifest)
    scope_holds = scope_holds_of(scope_revision, revisions, links, manifest)
    blocked = bool(facts[EFFECT_NOT_APPLIED])

    def supported(state, *, holds_count=True):
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
        return (complete and not scope_holds) or state not in RECOVERED or not holds_count

    # A recovered step whose scope no longer stands is followed by a return to the
    # investigation, and only by a step that answers something of what took it away: a
    # scope declared where there was none, evidence for an item a revision added. An
    # empty step answers nothing and moves nothing. A failed read-back is a blocker
    # whatever the scope, and is always recorded.
    lapse = [] if previous is None else lapsed(previous, revisions)
    if lapse and not blocked and all(hold in scope_holds for hold in lapse):
        return None
    # S1 lets nothing follow an accepted recovery, not even a reopen. That a scope
    # revision reopens one is the core's rule (``mythos_core.scope.check_scope_reopen``):
    # after an accepted step whose scope no longer stands, that rule is asked about it,
    # with each scope hold that stands against it, and S1's step check about no step.
    reopened = previous if lapse and previous.state in st.RECOVERY_TERMINAL else None
    follows = None if reopened is not None else previous
    state = st.UNDER_INVESTIGATION if lapse else _step(None if previous is None else previous.state, supported)
    if state is None:
        return None
    # The recovered state the step would have reached but for its coverage and scope
    # holds: the furthest one its witnesses support with the holds left out. None when no
    # hold stands, or none is supported even so.
    held_back_from = None
    if not complete or scope_holds:
        held_back_from = max(
            (one for one in RECOVERED if supported(one, holds_count=False)), key=_RANK.get, default=None
        )
    conditions = [
        {"condition": name, "witness": {"kind": kind, "ref": witness}}
        for name in dict.fromkeys((*_BASE, *_NEEDS[state]))
        for kind, witness in facts[name]
    ]
    items = scope_items(links, manifest, scope_revision, revisions)
    support, unvouched = support_of(
        conditions, links, items, recorded_by=recorded_by, recorded_at=recorded_at, previous=previous
    )
    gaps = [*links["gaps"], *(f"{EFFECT_NOT_APPLIED}:receipt:{r}" for _, r in facts[EFFECT_NOT_APPLIED])]
    gaps += [*holds, *scope_holds] if held_back_from else []
    # A witness nobody can be named for is not a support: it is a gap. So is a value of a
    # list carried from a step before SP-4 that is not a name, by its pointer.
    gaps += unvouched
    gaps += unnamed(gaps, links["restrictions"])
    reopens = str(previous.uuid) if previous is not None and state == st.UNDER_INVESTIGATION else ""
    try:
        recovery = st.Recovery(
            ref=ref, state=state, conditions=tuple(_condition_texts(conditions)), gaps=tuple(gaps),
            restrictions=tuple(links["restrictions"]),
            owner_acceptance=accepted if state == st.RECOVERY_ACCEPTED else "", reopens=reopens,
        )
        if follows is not None:
            st.check_recovery_step(_as_recovery(follows), recovery)
        if reopened is not None:
            core_scope.check_scope_reopen(_as_recovery(reopened), recovery, lapse)
    except (st.RecoveryError, core_scope.ScopeError) as exc:
        raise RecoveryRefused(exc.code, str(exc)) from None
    # The core's rule. The acceptance carries: it is in force when the step is recorded,
    # given under the scope revision the step is derived under, and no scope hold stands.
    release = release_of(
        state=state, gaps=gaps, held_back_from=held_back_from, acceptance_carries=bool(accepted) and not scope_holds
    )
    residual = [
        *({"statement": u["question"], "sources": [{"kind": "unknown", "ref": u["uuid"]}]} for u in links["unknowns"]),
        *({"statement": hold, "sources": [{"kind": "coverage", "ref": manifest.scope}]} for hold in holds),
        *({"statement": hold, "sources": [{"kind": "scope", "ref": manifest.scope}]} for hold in scope_holds),
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
        "release": release,
        "held_back_from": held_back_from or "",
        "support": support,
        "residual_uncertainty": residual,
        "scope_items": items,
    }


def _derived(row, previous, revisions) -> dict | None:
    # At the instant the step is recorded: whether the acceptance is in force then. A read
    # asks again at its own instant (served).
    in_force = row.accepted_by_id is not None and row.accepted_until is not None and row.accepted_until > row.recorded_at
    return derive(
        ref=str(row.uuid), links=row.links, manifest=manifest_of(row.finding, row.coverage),
        accepted=person_ref(row.accepted_by_id) if in_force else "", previous=previous,
        scope_revision=row.scope_revision, revisions=revisions, recorded_by=person_ref(row.recorded_by_id),
        recorded_at=row.recorded_at,
    )


def _stored(row) -> dict:
    return {
        "state": row.state, "reopens": row.reopens, "conditions": row.conditions, "gaps": row.gaps,
        "restrictions": row.restrictions, "release": row.release, "held_back_from": row.held_back_from,
        "support": row.support, "residual_uncertainty": row.residual_uncertainty, "scope_items": row.scope_items,
    }


def _references(row) -> tuple:
    """The person references a step keeps beside the accounts' keys, as they must be."""
    return person_ref(row.recorded_by_id), person_ref(row.accepted_by_id)


def check_derived(row) -> None:
    """Refuse ``row`` (unsaved) unless it names the incident's current scope revision
    (none when none is declared), every derived field is what :func:`derive` says of its
    own links, coverage, acceptance and recorder after the step before it, under that
    revision, and each person reference names the account its key names."""
    from .models import RecoveryRecord

    previous = RecoveryRecord.objects.filter(finding_id=row.finding_id, version__lt=row.version).order_by("-version").first()
    revisions = incident_scope.revisions_of([row.finding_id]).get(row.finding_id, [])
    try:
        current = row.links.get("incident") == str(row.finding.uuid) and row.scope_revision == incident_scope.current_of(revisions)
        derived = _derived(row, previous, revisions) if current else None
    except (KeyError, TypeError, AttributeError):
        derived = None
    if derived != _stored(row) or (row.recorded_by_ref, row.accepted_by_ref) != _references(row):
        raise RecoveryRefused(
            "not_derived",
            "a recovery step's state, conditions, gaps, restrictions, release, what it is held back from, who vouches "
            "for each witness and its residual uncertainty are derived from what it rests on, the step before it and "
            "the incident's current scope revision, and each person it names is the account its key names; this one "
            "says otherwise",
        )


def draft(finding, *, version, links, coverage=None, accepted_by=None, accepted_until=None, recorded_by=None,
          recorded_at=None, previous=None, revisions=()):
    """The next step of ``finding``'s recovery after ``previous``, unsaved, derived under
    the current one of ``revisions`` (the incident's scope revisions, oldest first; none
    given is no declared scope), with every derived field derived -- or None, when
    nothing may follow ``previous``."""
    from .models import RecoveryRecord

    row = RecoveryRecord(
        finding=finding, version=version, links=links, coverage=coverage or {}, accepted_by=accepted_by,
        accepted_until=accepted_until, recorded_by=recorded_by, recorded_at=recorded_at or timezone.now(),
        scope_revision=incident_scope.current_of(revisions),
    )
    row.recorded_by_ref, row.accepted_by_ref = _references(row)
    derived = _derived(row, previous, revisions)
    if derived is None:
        return None
    row.state, row.reopens, row.conditions = derived["state"], derived["reopens"], derived["conditions"]
    row.gaps, row.restrictions, row.release = derived["gaps"], derived["restrictions"], derived["release"]
    row.held_back_from, row.support = derived["held_back_from"], derived["support"]
    row.residual_uncertainty, row.scope_items = derived["residual_uncertainty"], derived["scope_items"]
    return row


def record(finding, *, by=None, body=None, accept_until=None) -> list:
    """Record the steps of ``finding``'s recovery that what ``body`` links now supports,
    one row per step, and return them. ``accept_until`` is the owner's acceptance, given
    by ``by``, which must be the deployment's owner. Refused, with nothing recorded, when
    nothing moves or a link or the acceptance is refused."""
    from .models import RecoveryRecord

    now = timezone.now()
    previous = RecoveryRecord.objects.filter(finding_id=finding.pk).order_by("-version").first()
    revisions = incident_scope.revisions_of([finding.pk]).get(finding.pk, [])
    # An accepted recovery is final for the scope revision it was accepted under, and
    # only for that one: once that scope no longer stands, steps are recorded again.
    if previous is not None and previous.state in st.RECOVERY_TERMINAL and not lapsed(previous, revisions):
        ended = previous.accepted_until is not None and previous.accepted_until <= now
        raise RecoveryRefused(
            "terminal",
            f"the recovery was accepted (step {previous.version}); nothing follows"
            + (
                ", not even a new acceptance once that one has ended: it reads as not accepted, and only a scope "
                "revision reopens it" if ended else ""
            ),
        )
    if accept_until is not None:
        if finding.deployment.owner_id is None:
            raise RecoveryRefused("no_owner", "no owner set for this deployment")
        if by is None or by.pk != finding.deployment.owner_id:
            raise RecoveryRefused("not_the_owner", "only the deployment's owner accepts its recovery")
        if accept_until <= now:
            raise RecoveryRefused("acceptance_ended", "an acceptance names an end in the future")
    links, coverage = resolve(finding, body, previous, now, by=by)
    steps = []
    try:
        with transaction.atomic():
            for _ in range(len(st.RECOVERY_STATES) + 1):
                row = draft(
                    finding, version=1 if previous is None else previous.version + 1, links=links, coverage=coverage,
                    accepted_by=by if accept_until is not None else None, accepted_until=accept_until,
                    recorded_by=by, recorded_at=now, previous=previous, revisions=revisions,
                )
                if row is None:
                    break
                row.save()
                steps.append(row)
                previous = row
    except IntegrityError:
        raise RecoveryRefused("raced", "another step of this recovery was recorded at the same time") from None
    if not steps:
        lapse = lapsed(previous, revisions)
        if lapse:
            raise RecoveryRefused(
                "nothing_moved",
                f"nothing moved: step {previous.version} ({previous.state}) no longer stands under the incident's "
                f"scope, and this step answers none of what took it away: {lapse}. An item a revision added stays "
                "open until a step links something that names it: evidence of a finding on that asset, a permit of "
                "that workflow, or the asset observed in a coverage manifest posted since",
            )
        raise RecoveryRefused(
            "nothing_moved",
            f"nothing moved: what this step rests on supports no state that may follow {previous.state!r}",
        )
    return steps


# ------------------------------------------------------------------ the reads


def _held_of(row) -> str | None:
    """What a step that still stands is held back from: as it recorded it; for a step
    recorded before SP-4, exactly what the rule that wrote it meant. Under that rule (and
    under the core's) a step that is not accepted reads ``AUDIT_INCOMPLETE`` only when it
    is held back, and it is held back from ``recovery_accepted`` when its own acceptance
    was in force when it was recorded (the one witness acceptance adds to a tested repair),
    else from ``restored_with_restrictions``. Pure."""
    if row.held_back_from is not None:
        return row.held_back_from if row.held_back_from in RECOVERED and row.held_back_from != row.state else None
    if row.release != st.AUDIT_INCOMPLETE or row.state == st.RECOVERY_ACCEPTED:
        return None
    in_force = row.accepted_until is not None and row.accepted_until > row.recorded_at
    held = st.RECOVERY_ACCEPTED if in_force else st.RESTORED_WITH_RESTRICTIONS
    return None if held == row.state else held


def _read_support(row) -> tuple[list | None, list[str], list[str]]:
    """``(support, sentences, gaps)`` for a step as a read serves it: each support entry
    with the sentence every reader prints for it (the core's ``support_sentence``), and the
    gap each witness leaves that no voucher is on record for. A step recorded before SP-4
    names no voucher, so every witness of it is such a gap (the core's reading of an
    unknown voucher), and its support is None, never an empty list. A stored entry the core
    cannot read is a gap too. Pure."""
    core = _receipt()
    if not isinstance(row.support, list):
        return None, [], [_support_gap(*witness) for witness in _witnesses(row.conditions, row.scope_items)]
    support, sentences, gaps = [], [], []
    for entry in row.support:
        try:
            sentences.append(core.support_sentence(entry))
            support.append(entry)
        except core.RecoveryReceiptError:
            held = entry if isinstance(entry, dict) else {}
            gaps.append(_support_gap(held.get("condition"), held.get("kind"), held.get("ref")))
    return support, sentences, gaps


def _served_release(state, gaps, held_back_from) -> str:
    """The release a read serves: the core's rule over what it serves. Where the core
    refuses what the row holds (only a row written past its guards can hold that), the
    release cannot be read, and it reads ``AUDIT_INCOMPLETE``: caution, never a pass and
    never a failure nothing showed."""
    try:
        return release_of(
            state=state, gaps=gaps, held_back_from=held_back_from, acceptance_carries=state == st.RECOVERY_ACCEPTED
        )
    except RecoveryRefused:
        return st.AUDIT_INCOMPLETE


def _served_ref(stored, user_id):
    """A person's reference as a read serves it: the one the row keeps, else (a row from
    before SP-4) the account's key while the account exists; None for nobody."""
    if stored is not None:
        return stored or None
    return person_ref(user_id) or None


def standing_of(row, *, last: bool, current_revision, at) -> str:
    """How ``row`` stands at the reader's instant ``at``, in the core's words and the core's
    order (``mythos_core.recovery_receipt.receipt_standing``), with the record's head: the
    latest step, and the incident's ``current_revision`` (None: none declared).

    ``superseded`` when a later step is the latest; then ``acceptance_ended`` when the step
    carries an acceptance that has ended by ``at``; ``unknown`` when the scope is behind the
    revision the step was taken under (a head behind the step is not the head);
    ``scope_moved`` when a revision was declared since; else ``current``. Pure."""
    core = _receipt()
    if not last:
        return core.SUPERSEDED
    if row.accepted_until is not None and at >= row.accepted_until:
        return core.ACCEPTANCE_ENDED
    taken = row.scope_revision
    if current_revision == taken:
        return core.CURRENT
    if current_revision is None or (taken is not None and current_revision < taken):
        return core.UNKNOWN
    return core.SCOPE_MOVED


def served(row, scope_gaps, held_at=st.UNDER_INVESTIGATION, *, at=None, standing=None) -> dict:
    """One step as its reads serve it at the reader's instant ``at`` (now when None):
    every derived field, what it rests on, its coverage manifest with what
    ``coverage.coverage_ratio`` measures of it, who vouches for each witness, and who
    accepted and recorded it (``None`` when nobody is on record). No summary badge: the
    state is one of S1's words, beside its conditions and gaps.

    ``scope_gaps`` is what about the incident's scope holds a recovered state back for
    this step now (:func:`scope_holds_of`), and it is served with the
    step's ``scope_revision`` whatever the step's state. Where the step is a recovered
    state and any stands, the step is not served as recovered: its ``state`` is
    ``held_at`` (the last state before it that was not a recovered one), its ``gaps``
    name each, and it is held back from the state it recorded. Where the step is
    accepted and its acceptance has ended by ``at``, it is not served as accepted either:
    its ``state`` is ``held_at`` and it is held back from nothing. Its ``release`` is the
    core's over what is served, in every case (:func:`release_of`); ``standing`` is the
    core's word for how it stands (:func:`standing_of`, as the last step when not given).
    ``recorded`` is what the row holds, always: the row is history and is not
    rewritten."""
    measured = cov.coverage_ratio(manifest_of(row.finding, row.coverage))
    scope_gaps = list(scope_gaps)
    at = timezone.now() if at is None else at
    scope_lapsed = row.state in RECOVERED and bool(scope_gaps)
    acceptance_lapsed = (
        row.state == st.RECOVERY_ACCEPTED and row.accepted_until is not None and row.accepted_until <= at
    )
    support, sentences, unvouched = _read_support(row)
    recorded_gaps = [*row.gaps, *(gap for gap in unvouched if gap not in row.gaps)]
    recorded_gaps += [pointer for pointer in unnamed(recorded_gaps, row.restrictions) if pointer not in recorded_gaps]
    gaps = [*recorded_gaps, *scope_gaps] if scope_lapsed else recorded_gaps
    if acceptance_lapsed:
        state, held_back_from = held_at, None
    elif scope_lapsed:
        state, held_back_from = held_at, row.state
    else:
        state, held_back_from = row.state, _held_of(row)
    if standing is None:
        standing = standing_of(row, last=True, current_revision=row.scope_revision, at=at)
    return {
        "ref": str(row.uuid),
        "version": row.version,
        "state": state,
        "reopens": row.reopens or None,
        "conditions": row.conditions,
        "gaps": gaps,
        "restrictions": row.restrictions,
        "release": _served_release(state, gaps, held_back_from),
        # The recovered state the step would have reached but for a gap or a scope hold
        # among its gaps, or None. The core's word and value.
        "held_back_from": held_back_from,
        "standing": standing,
        # Who vouches for each witness, in the core's entry shape, and the sentence every
        # reader prints for each (the core's). None on a step recorded before SP-4.
        "support": support,
        "support_sentences": sentences,
        # Every gap as a name (free text by its pointer), with what would close it; and a
        # scope that is not declared, or cannot be read, said as one whatever the state
        # (the core's rule for a receipt: unknown is never ok).
        "gaps_named": [
            {"gap": gap, "would_close": would_close(gap)}
            for gap in dict.fromkeys(
                (*gaps, *(hold for hold in scope_gaps if hold in (core_scope.NOT_DECLARED, core_scope.UNREADABLE)))
            )
            if is_name(gap)
        ],
        "scope_revision": row.scope_revision,
        "scope_gaps": scope_gaps,
        # As recorded: each item the scope gained, with the kind of link that names it
        # (finding evidence, a permit, or a coverage observation with nothing found), and
        # each item it lost, with who removed it and why. Each list is None where it
        # could not be established (no declared scope, or an unreadable one). The whole
        # value is None on a row from before SP-3.
        "scope_items": row.scope_items,
        "recorded": {"state": row.state, "gaps": row.gaps, "release": row.release},
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
        "accepted_by_ref": _served_ref(row.accepted_by_ref, row.accepted_by_id),
        "accepted_until": row.accepted_until.isoformat() if row.accepted_until else None,
        "recorded_by": row.recorded_by.username if row.recorded_by_id else None,
        "recorded_by_ref": _served_ref(row.recorded_by_ref, row.recorded_by_id),
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


def served_steps(steps: list, revisions: list, at=None) -> list[dict]:
    """Every step of one incident, oldest first, as its reads serve it at the reader's
    instant ``at`` (now when None) under the incident's scope ``revisions`` (oldest
    first): each with the scope revision it was derived under, what holds it back now and
    how it stands (:func:`served`)."""
    at = timezone.now() if at is None else at
    current = incident_scope.current_of(revisions)
    held_at, out = st.UNDER_INVESTIGATION, []
    for index, step in enumerate(steps):
        holds = scope_holds_of(step.scope_revision, revisions, step.links, manifest_of(step.finding, step.coverage))
        standing = standing_of(step, last=index == len(steps) - 1, current_revision=current, at=at)
        out.append(served(step, holds, held_at, at=at, standing=standing))
        if step.state not in RECOVERED:
            held_at = step.state
    return out


def _incident(finding, steps: list, revisions: list, at) -> dict:
    read = served_steps(steps, revisions, at)
    last = read[-1] if read else None
    return {
        "finding": str(finding.uuid),
        "title": finding.title,
        "severity": finding.severity,
        # The reader's instant every step is read at, in the core's one form: an
        # acceptance that ended by then is read as ended.
        "as_of": instant(at),
        # The incident's current scope revision; None when no scope is declared.
        "scope_revision": incident_scope.current_of(revisions),
        # Every item a revision added and a later one removed: both revision numbers, who
        # removed it and why. Disclosed with the record; never a gap. None, never an
        # empty list, when no scope is declared or a revision cannot be read: an empty
        # list says that nothing was removed, and that is then not known.
        "scope_removed": incident_scope.removed(revisions) if revisions else None,
        # As the last step reads now, never as a recovered state its scope has left behind.
        "current": None if last is None else {"version": last["version"], "state": last["state"], "release": last["release"]},
        "steps": read,
    }


def finding_record(finding) -> dict:
    """One incident's recovery record: every step, oldest first, each with the scope
    revision it was derived under, and the incident's current one, read at the server's
    clock now. Three queries."""
    at = timezone.now()
    steps = _steps_of([finding.pk]).get(finding.pk, [])
    revisions = incident_scope.revisions_of([finding.pk]).get(finding.pk, [])
    return {"deployment": str(finding.deployment.uuid), **_incident(finding, steps, revisions, at)}


def recorded_steps(finding, steps: list) -> list[dict]:
    """The ``steps`` just recorded for ``finding``, as its read serves them."""
    versions = {step.version for step in steps}
    return [step for step in finding_record(finding)["steps"] if step["version"] in versions]


def deployment_records(deployment, *, offset: int, page_size: int) -> dict:
    """The deployment's incidents -- its findings that have a recovery record -- one page
    of them, each with every step oldest first and its current scope revision, and how
    many there are: the count and the page are of this deployment's incidents only, each
    read at the same instant, the server's clock now. Four queries."""
    from django.db.models import Exists, OuterRef

    from .history_reads import _envelope, _page
    from .models import Finding, RecoveryRecord

    incidents = Finding.objects.filter(
        Exists(RecoveryRecord.objects.filter(finding_id=OuterRef("pk"))), deployment_id=deployment.pk
    ).order_by("id")
    page, total = _page(incidents, offset, page_size)
    steps = _steps_of([finding.pk for finding in page])
    revisions = incident_scope.revisions_of([finding.pk for finding in page])
    at = timezone.now()
    read = [_incident(f, steps.get(f.pk, []), revisions.get(f.pk, []), at) for f in page]
    return _envelope(deployment, "incidents", read, total, offset, page_size)
