"""The persistence half of :mod:`assurance.authority_chain`: load, record, publish.

:mod:`assurance.authority_chain` states the verification rule and is pure. This
module is the thin layer that hands it what it reads, and nothing it decides is
decided here:

* :func:`load_inputs` reads the graph the hop checks are made against -- the route
  map's declared and inferred edges and its unresolved references
  (:func:`assurance.route.build_route_map`), each principal's effective reach
  (:func:`assurance.access.assess_effective_access`), shadow and assessed per
  component (:func:`assurance.governance.is_shadow`,
  :func:`assurance.coverage.coverage_manifest`) -- with the approvals and the
  contracts they bind (:mod:`assurance.tool_contract`) and the outcomes the chains
  cite, each at its basis IN FORCE (:func:`assurance.observed_outcomes.basis_in_force`).
* :func:`read_chains` reads every recorded chain, decides which stand
  (:func:`assurance.authority_chain.in_force`) and verifies each.
* :func:`record_chain` appends one, typed in (``attested``) or signed by an engine
  (``demonstrated``: the envelope :mod:`assurance.observed_outcomes` verifies, with
  the chain's own digest as its evidence digest).
* :func:`authority_chain_signal` is what the decision reads
  (:func:`assurance.decision.claim_decision_signal`), and :func:`receipt_reference`
  what the receipt carries.

A deployment with no recorded chain reads ONE query here and nothing else: no
graph, no access, no coverage. The decision of a deployment nobody recorded a
chain for is exactly what it was before chains existed.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db.models import Prefetch
from mythos_core import outcome as _oc

from . import authority_chain as rule
from . import composition as _composition
from . import observed_outcomes
from .models import AuthorityChain, ToolContractBinding, WorkflowChainOutcome
from .receipt import _digest


class ChainRefused(ValueError):
    """A chain this deployment will not record, and why. Raised inside the write's
    transaction, so a refused chain in a batch records none of the batch."""


# ------------------------------------------------------------ digests and documents


def approval_digest(workflow, bindings) -> str:
    """The version of an approval a chain's policy node names: SHA-256 over what was
    approved -- the workflow, what it is approved to do, and every tool it binds
    with the contract it binds it under. The display name is not in it: renaming an
    approval approves nothing new. Re-approving a tool under a changed contract, or
    rewriting what the workflow is approved to do, is a new version."""
    return _digest(
        {
            "slug": workflow.slug,
            "description": workflow.description or "",
            "tools": sorted([b.tool_kind, b.tool_identifier, b.contract_digest] for b in bindings),
        }
    )


def chain_document(deployment_uuid: str, workflow: str, hops, gate_outcome_id: str, effect_outcome_id: str) -> dict:
    """The document a chain's digest is taken over and an engine's signature covers:
    the deployment, the workflow, every hop as written, and the outcomes it cites."""
    return {
        "schema": rule.CHAIN_SCHEMA,
        "deployment": deployment_uuid,
        "workflow": workflow,
        "hops": [hop.as_dict() if isinstance(hop, rule.Hop) else hop for hop in hops],
        "gate_outcome_id": gate_outcome_id or "",
        "effect_outcome_id": effect_outcome_id or "",
    }


def chain_digest(document: dict) -> str:
    """``sha256:`` + hex over the document's canonical bytes -- the form
    :func:`mythos_core.outcome.evidence_digest_of` gives, so a signed outcome's
    ``evidence_digest`` can name a chain."""
    return _oc.evidence_digest_of(document)


def _row_digest(row, deployment_uuid: str) -> str:
    return chain_digest(
        chain_document(deployment_uuid, row.workflow, row.hops, row.gate_outcome_id, row.effect_outcome_id)
    )


# ------------------------------------------------------------------- the inputs


def _permissions(metadata) -> tuple[str, ...] | None:
    """A component's declared permissions, or ``None`` when it declares none."""
    if not isinstance(metadata, dict):
        return None
    raw = metadata.get("permissions")
    if not isinstance(raw, list):
        return None
    return tuple(p for p in raw if isinstance(p, str))


def load_inputs(deployment, cited_ids, keyring) -> rule.Inputs:
    """Everything :func:`assurance.authority_chain.verify` reads, for ``deployment``.

    ``cited_ids``: the outcome ids the chains cite (their gate decisions and
    observed effects). ``keyring``: the one the decision is read under, so a
    citation verifies against the same keys as the composition beside it."""
    from .access import assess_effective_access
    from .coverage import coverage_manifest
    from .governance import is_shadow
    from .graph_refs import in_graph
    from .route import build_route_map
    from .tool_contract import current_digests

    assets = in_graph(list(deployment.assets.all()))
    unassessed = {entity["asset_uuid"] for entity in coverage_manifest(deployment)["unassessed"]}
    components = tuple(
        rule.Component(
            uuid=str(a.uuid),
            kind=a.kind,
            name=a.name,
            identifier=a.identifier or "",
            classification=a.classification,
            shadow=is_shadow(a.classification),
            assessed=str(a.uuid) not in unassessed,
            permissions=_permissions(a.metadata),
        )
        for a in assets
    )
    route = build_route_map(deployment)
    declared = frozenset((e["source"], e["kind"], e["target"]) for e in route["edges"] if e["declared"])
    inferred = frozenset((e["source"], e["target"]) for e in route["edges"] if not e["declared"])
    # The route map names a gap's source by name and kind; every component that
    # answers to both carries it, so an ambiguous name never drops a gap.
    by_source: dict[tuple[str, str], list[str]] = {}
    for a in assets:
        by_source.setdefault((a.name, a.kind), []).append(str(a.uuid))
    gaps: dict[str, list[rule.Gap]] = {}
    for row in route["unresolved"]:
        for uuid in by_source.get((row["source"], row["source_kind"]), []):
            gaps.setdefault(uuid, []).append(
                rule.Gap(row["mechanism"], row["reference"], tuple(row.get("reasons") or [row["reason"]]))
            )
    access = assess_effective_access(deployment)
    reach = {
        principal["key"].split(":", 1)[1]: frozenset(
            r["target_uuid"] for r in principal["effective_reach"] if r.get("target_uuid")
        )
        for principal in access["principals"]
        if principal["key"].startswith("asset:")
    }
    graph = rule.Graph(
        components=components,
        declared=declared,
        inferred=inferred,
        gaps={uuid: tuple(found) for uuid, found in gaps.items()},
        reach=reach,
    )

    digests = current_digests(deployment)
    approvals = {}
    for workflow in deployment.approved_workflows.prefetch_related(
        Prefetch(
            "tool_contract_bindings",
            queryset=ToolContractBinding.objects.filter(released_at__isnull=True)
            .select_related("contract")
            .order_by("tool_kind", "tool_identifier"),
            to_attr="live_tool_bindings",
        )
    ):
        live = workflow.live_tool_bindings
        approvals[workflow.slug] = rule.Approval(
            slug=workflow.slug,
            digest=approval_digest(workflow, live),
            tools=tuple(
                rule.ApprovedTool(
                    kind=b.tool_kind,
                    identifier=b.tool_identifier,
                    approved_digest=b.contract_digest,
                    current_digest=digests.get((str(b.tool_kind), str(b.tool_identifier))),
                    permissions=_permissions(b.contract.contract if b.contract is not None else None),
                )
                for b in live
            ),
        )

    outcomes = {}
    ids = sorted({i for i in cited_ids if i})
    if ids:
        deployment_uuid = str(deployment.uuid)
        for row in WorkflowChainOutcome.objects.filter(deployment=deployment, outcome_id__in=ids):
            basis = observed_outcomes.basis_in_force(row, keyring, deployment_uuid=deployment_uuid)
            outcomes[row.outcome_id] = rule.CitedOutcome(
                outcome_id=row.outcome_id,
                workflow=row.workflow,
                status=row.status,
                evidence=_composition.evidence_kind(basis, row.observer_engine),
            )
    return rule.Inputs(graph=graph, approvals=approvals, outcomes=outcomes)


# --------------------------------------------------------------------- reading


@dataclass(frozen=True)
class Recorded:
    """One recorded chain, as read: the row, whether it stands, what it rests on,
    and its verdict."""

    row: AuthorityChain
    standing: bool
    basis: str
    verdict: rule.ChainVerdict


def basis_in_force(row, keyring, deployment_uuid: str) -> str:
    """``demonstrated`` only while an envelope a trusted engine signed verifies NOW
    and covers THIS chain: its outcome names this deployment, this workflow and, as
    its evidence digest, the digest of the chain the row holds -- recomputed from
    the row, not read from its column. Otherwise ``attested``: a chain someone
    recorded, which is what a row whose signature no longer verifies then is."""
    if row.basis != _composition.BASIS_DEMONSTRATED or not keyring or not row.outcome_id:
        return _composition.BASIS_ATTESTED
    if not isinstance(row.envelope, dict):
        return _composition.BASIS_ATTESTED
    verdict = observed_outcomes._verified(row.envelope, keyring)
    if verdict.verdict != _oc.AUTHENTIC or verdict.outcome is None:
        return _composition.BASIS_ATTESTED
    signed = verdict.outcome
    digest = _row_digest(row, deployment_uuid)
    covers = (
        signed["outcome_id"] == row.outcome_id
        and signed["deployment"] == deployment_uuid
        and signed["workflow"] == row.workflow
        and signed["status"] == _oc.HELD
        and signed["evidence_digest"] == digest == row.digest
        and signed["observer"]["engine"] == row.observer_engine
        and verdict.key_id == row.observer_key_id
    )
    return _composition.BASIS_DEMONSTRATED if covers else _composition.BASIS_ATTESTED


def read_chains(deployment, keyring=observed_outcomes.READ_KEYRING, *, with_recorder: bool = False) -> list[Recorded]:
    """Every chain recorded for ``deployment``, oldest first, each verified.

    One query when there is none. Otherwise the graph, access, coverage, approvals
    and cited outcomes are read ONCE for all of them. ``with_recorder`` joins who
    recorded each chain, for a route that publishes it; the decision never reads it,
    so it reads no user table."""
    rows = AuthorityChain.objects.filter(deployment=deployment).order_by("id")
    rows = list(rows.select_related("recorded_by") if with_recorder else rows)
    if not rows:
        return []
    if keyring is observed_outcomes.READ_KEYRING:
        keyring = observed_outcomes.trusted_keyring()
    from .served_route import serving_route_now
    from .workflow_chains import route_of

    serving = serving_route_now(deployment)
    chains = {
        row.pk: rule.Chain(
            workflow=row.workflow,
            hops=rule.hops_from_stored(row.hops),
            gate_outcome_id=row.gate_outcome_id,
            effect_outcome_id=row.effect_outcome_id,
            route=route_of(row, serving),
        )
        for row in rows
    }
    standing, _ = rule.in_force([(pk, chain) for pk, chain in chains.items()])
    inputs = load_inputs(
        deployment,
        {i for row in rows for i in (row.gate_outcome_id, row.effect_outcome_id)},
        keyring,
    )
    deployment_uuid = str(deployment.uuid)
    stands = set(standing)
    return [
        Recorded(
            row=row,
            standing=row.pk in stands,
            basis=basis_in_force(row, keyring, deployment_uuid),
            verdict=rule.verify(chains[row.pk], inputs),
        )
        for row in rows
    ]


def authority_chain_signal(deployment, keyring=observed_outcomes.READ_KEYRING) -> dict:
    """The chains in force, by verdict. What the decision caps on
    (:data:`assurance.decision.CLAIM_CAPS`): a broken chain and an unproven one. A
    superseded chain caps nothing; it is published, not decided with."""
    standing = [r for r in read_chains(deployment, keyring) if r.standing]
    return {
        "broken": [r for r in standing if r.verdict.verdict == rule.BROKEN],
        "unproven": [r for r in standing if r.verdict.verdict == rule.UNPROVEN],
        "proven": [r for r in standing if r.verdict.verdict == rule.PROVEN],
    }


# --------------------------------------------------------------------- writing


def record_chain(deployment, data: dict, *, actor, now, keyring=None) -> AuthorityChain:
    """Append one chain. ``data`` is what :class:`AuthorityChainSerializer` validated:
    ``workflow``, ``hops`` (parsed), and optionally the outcomes it cites, when the
    effect was produced, a source, a note and an ``envelope``.

    With an envelope the chain is ``demonstrated``, and only if the envelope is a
    signed outcome a trusted engine made for THIS deployment (every check
    :mod:`assurance.observed_outcomes` makes of an outcome: authenticity, the
    deployment, clock skew, age), names this workflow, reports ``held``, and names
    as its evidence digest the digest of exactly this chain. Anything else is
    refused rather than recorded as attested: an envelope that does not cover the
    chain beside it is a claim to a signature the chain does not have.

    Must run inside the caller's transaction (the route's): the served route is
    noted and bound here (:func:`assurance.served_route.routes_for_outcomes`), as an
    outcome's is."""
    from .served_route import routes_for_outcomes

    hops = data["hops"]
    workflow = data["workflow"]
    gate, effect = data.get("gate_outcome_id") or "", data.get("effect_outcome_id") or ""
    deployment_uuid = str(deployment.uuid)
    digest = chain_digest(chain_document(deployment_uuid, workflow, hops, gate, effect))
    observed_at = data.get("observed_at")
    signed = {}
    envelope = data.get("envelope")
    if envelope is not None:
        keyring = keyring if keyring is not None else observed_outcomes.load_keyring()
        outcome, key_id, why = observed_outcomes._examine(envelope, deployment, keyring, now)
        if outcome is None:
            raise ChainRefused(why)
        if outcome["workflow"] != workflow:
            raise ChainRefused(f"the envelope signs workflow {outcome['workflow']!r}; this chain serves {workflow!r}")
        if outcome["status"] != _oc.HELD:
            raise ChainRefused(
                f"the envelope reports {outcome['status']!r}. An engine signs a chain it observed hold; an "
                "outcome that did not hold is posted to chain-outcomes"
            )
        if outcome["evidence_digest"] != digest:
            raise ChainRefused(
                f"the envelope's evidence digest is {outcome['evidence_digest']}; this chain's digest is {digest}. "
                "The signature covers another chain"
            )
        if AuthorityChain.objects.filter(outcome_id=outcome["outcome_id"]).exists():
            raise ChainRefused(f"outcome {outcome['outcome_id']} was already recorded as a chain")
        instant = observed_outcomes._instant(outcome["observed_at"])
        if observed_at is not None and observed_at != instant:
            raise ChainRefused(
                f"observed_at is {observed_at.isoformat()}; the envelope signs {instant.isoformat()}"
            )
        observed_at = instant
        signed = {
            "basis": _composition.BASIS_DEMONSTRATED,
            "outcome_id": outcome["outcome_id"],
            "observer_engine": outcome["observer"]["engine"],
            "observer_key_id": key_id,
            "envelope": envelope,
        }
    route = routes_for_outcomes(deployment, [observed_at], now=now)[0]
    return AuthorityChain.objects.create(
        deployment=deployment,
        workflow=workflow,
        effect=hops[-1].target.ref,
        hops=[hop.as_dict() for hop in hops],
        digest=digest,
        gate_outcome_id=gate,
        effect_outcome_id=effect,
        observed_at=observed_at,
        route_fingerprint=route,
        source=data.get("source", ""),
        note=data.get("note", ""),
        recorded_by=actor,
        recorded_at=now,
        **({"basis": _composition.BASIS_ATTESTED} | signed),
    )


# ------------------------------------------------------------------ publishing


def _reading(r: rule.Reading) -> dict:
    return {"verdict": r.verdict, "code": r.code, "detail": r.detail}


def hop_payload(h: rule.HopVerdict) -> dict:
    return {
        "index": h.index,
        **h.hop.as_dict(),
        "verdict": h.verdict,
        "proven_by": [_reading(r) for r in h.proven_by],
        "reasons": [_reading(r) for r in h.reasons],
    }


def chain_payload(recorded: Recorded) -> dict:
    """One recorded chain as the route publishes it: the chain, every hop with its
    verdict and why, and which hops are unproven or broken -- named, so a reader can
    go to the hop rather than infer it."""
    row, verdict = recorded.row, recorded.verdict
    return {
        "uuid": str(row.uuid),
        "workflow": row.workflow,
        "effect": row.effect,
        "digest": row.digest,
        "standing": recorded.standing,
        "verdict": verdict.verdict,
        "basis": row.basis,
        "basis_in_force": recorded.basis,
        "signed": recorded.basis == _composition.BASIS_DEMONSTRATED,
        "observer_engine": row.observer_engine or None,
        "outcome_id": row.outcome_id,
        "gate_outcome_id": row.gate_outcome_id or None,
        "effect_outcome_id": row.effect_outcome_id or None,
        "route": verdict.chain.route,
        "observed_at": row.observed_at.isoformat() if row.observed_at else None,
        "recorded_at": row.recorded_at.isoformat() if row.recorded_at else None,
        "recorded_by": row.recorded_by.username if row.recorded_by_id else None,
        "source": row.source,
        "note": row.note,
        "unproven_hops": [h.index for h in verdict.unproven],
        "broken_hops": [h.index for h in verdict.broken],
        "hops": [hop_payload(h) for h in verdict.hops],
    }


def chain_brief(recorded: Recorded) -> dict:
    """A chain for the decision-support view: which one, and the hops that hold it."""
    verdict = recorded.verdict
    return {
        "uuid": str(recorded.row.uuid),
        "workflow": recorded.row.workflow,
        "effect": recorded.row.effect,
        "digest": recorded.row.digest,
        "verdict": verdict.verdict,
        "hops": [
            {
                "index": h.index,
                "relation": h.hop.relation,
                "from": h.hop.source.as_dict(),
                "to": h.hop.target.as_dict(),
                "verdict": h.verdict,
                "reasons": [r.code for r in h.reasons],
            }
            for h in verdict.hops
            if h.verdict != rule.PROVEN
        ],
    }


def summary(read: list[Recorded]) -> dict:
    standing = [r for r in read if r.standing]
    return {
        "recorded": len(read),
        "standing": len(standing),
        "superseded": len(read) - len(standing),
        # Every verdict, zeros included: a count that appears only when non-zero
        # reads exactly like a zero when it is missing.
        "verdict_census": {
            v: sum(1 for r in standing if r.verdict.verdict == v) for v in sorted(rule.HOP_VERDICTS)
        },
    }


def receipt_reference(deployment, *, limit: int) -> dict:
    """The chains in force as the receipt carries them: each chain by its digest,
    every hop by relation, node kinds, verdict and the codes of what proves it or
    holds it -- and no node's name. The names are the customer's vocabulary on an
    artifact built to travel; the digest names the chain exactly, and the
    deployment's authority-chains route serves the chain the digest is taken over.

    Ordered by digest, so the same chains always serialise the same; at most
    ``limit`` of them, with how many were not shown."""
    read = read_chains(deployment)
    standing = sorted((r for r in read if r.standing), key=lambda r: r.row.digest)
    shown = standing[:limit]
    return {
        **summary(read),
        "basis_census": {
            b: sum(1 for r in standing if r.basis == b)
            for b in sorted({_composition.BASIS_DEMONSTRATED, _composition.BASIS_ATTESTED})
        },
        "chains": [
            {
                "digest": r.row.digest,
                "basis": r.basis,
                "verdict": r.verdict.verdict,
                "hops": [
                    {
                        "relation": h.hop.relation,
                        "from_kind": h.hop.source.kind,
                        "to_kind": h.hop.target.kind,
                        "verdict": h.verdict,
                        "readings": [x.code for x in (h.proven_by if h.verdict == rule.PROVEN else h.reasons)],
                    }
                    for h in r.verdict.hops
                ],
            }
            for r in shown
        ],
        "not_shown": len(standing) - len(shown),
    }
