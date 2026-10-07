"""A tool's effective contract, and the authority bound to it (SPINE, cross-cutting).

The deployment-wide invalidation (:mod:`assurance.invalidation`) binds every claim
to the inputs its deriver reads and to the policy in force. None of that sees what
a tool registration may DO: its input and output schema, the effect class it
declares, its MCP annotations. A tool is an :class:`~assurance.models.Asset` keyed
by ``(kind, identifier)``, and that key is stable while the contract under it
moves -- the same ``refund@payments`` row re-declared with a wider schema or a
destructive effect class is, by name and by registry entry, the tool somebody
approved. A stable tool name or registry entry does not prove stable authority.

So this module:

- **computes the contract** (:func:`contract_descriptor`, :func:`contract_digest`):
  a SHA-256 over the canonical JSON (sorted keys, compact separators -- the
  :func:`assurance.receipt._digest` discipline) of the fields that define what the
  tool may do. A field nobody declared is carried as ``None`` rather than
  omitted, so declaring one is a contract change;
- **records it per registration, append-only** (:func:`record_tool_contracts`,
  :class:`~assurance.models.ToolContract`): a new row whenever the digest differs
  from the last one recorded for that registration;
- **binds approvals and claims to it** (:func:`bind_claim`, :func:`bind_workflow`):
  the binding records the digest the approval or claim was made under. An
  approval made over HTTP binds through :func:`approve_workflow_tools`, which the
  approved-workflows route calls with the tools each workflow names;
- **finds what a contract change supersedes** (:func:`superseded_bindings`): live
  bindings whose digest is not the tool's current one -- decided live, off the
  asset rows, so nothing that writes a claim row can lift it;
- **invalidates precisely** (:func:`invalidate_superseded`, called by
  :func:`assurance.invalidation.check_invalidations`): for exactly the claims
  bound to a superseded contract it opens a retest (once per claim identity,
  through the existing guard) whose reason names the tool and both digests, and
  moves the claim to STALE through the existing seam. A claim bound only to other
  tools is not touched by this path.

It ADDS precision. It never removes an invalidation: the deployment-wide path in
:func:`assurance.invalidation.check_invalidations` runs first and unchanged, and
nothing here moves a claim toward a pass, resolves an obligation, or reads, holds
or writes a stop, a pause or a revocation. A REVOKED claim is never invalidated.
"""

from __future__ import annotations

import json

from django.db import transaction
from django.utils import timezone

from .graph_refs import in_graph
from .models import (
    ApprovedWorkflow,
    Asset,
    AssuranceClaim,
    ClaimEvent,
    ToolContract,
    ToolContractBinding,
)
from .receipt import _digest

#: The registration kinds that carry a tool contract: what an agent can call.
TOOL_KINDS = frozenset({Asset.Kind.TOOL, Asset.Kind.MCP_SERVER, Asset.Kind.SKILL})

#: The version of the descriptor below. In the descriptor, so a change to what is
#: hashed moves every digest rather than silently re-reading old ones.
CONTRACT_VERSION = 1

#: The metadata fields that define what a tool may do, as the declaration writes
#: them (:func:`assurance.assets._agent_and_tools`). ``permissions`` and ``server``
#: are the reach the effective-access graph already follows; the schemas, the
#: declared effect class and the MCP annotations (read-only / destructive /
#: idempotent / open-world hints) are what no fingerprint saw before.
CONTRACT_FIELDS = ("input_schema", "output_schema", "effect_class", "annotations", "permissions", "server")

#: What the reason says for a tool that is no longer registered at all.
NOT_REGISTERED = "none (the tool is no longer registered)"


def is_tool(asset) -> bool:
    return getattr(asset, "kind", None) in TOOL_KINDS


def _canonical_set(values) -> list:
    """A declared set (permissions) in a stable order, distinct values once. A
    value that is not a list is kept as it is: a malformed declaration is part of
    the contract too, and normalising it away would hide a change."""
    if not isinstance(values, list):
        return values
    seen = {}
    for value in values:
        seen.setdefault(json.dumps(value, sort_keys=True, default=str), value)
    return [seen[key] for key in sorted(seen)]


def contract_descriptor(asset) -> dict:
    """The fields that define what ``asset`` (a tool registration) may do.

    Keyed by the registration (kind and identifier) so the digest is tied to it;
    never the display name, a timestamp, a row id or the classification -- an
    approval is what is bound TO the contract, not part of it."""
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    descriptor = {
        "contract_version": CONTRACT_VERSION,
        "kind": asset.kind,
        "identifier": asset.identifier,
    }
    for name in CONTRACT_FIELDS:
        value = metadata.get(name)
        descriptor[name] = _canonical_set(value) if name == "permissions" else value
    return descriptor


def contract_digest(asset) -> str:
    """SHA-256 (hex) over the canonical JSON of :func:`contract_descriptor`."""
    return _digest(contract_descriptor(asset))


def _key(kind, identifier) -> tuple[str, str]:
    return (str(kind), str(identifier))


def current_tools(deployment, *, assets=None) -> dict[tuple[str, str], Asset]:
    """Every tool registration in the deployment's graph, by ``(kind, identifier)``.
    Reads ``deployment.assets.all()``, so a prefetched deployment costs nothing;
    ``assets`` overrides it for a caller whose prefetch predates its own writes."""
    rows = deployment.assets.all() if assets is None else assets
    return {
        _key(a.kind, a.identifier): a
        for a in in_graph(rows)
        if is_tool(a) and a.identifier
    }


def current_digests(deployment) -> dict[tuple[str, str], str]:
    """The contract digest in force for every tool registration, read off the
    registration rows now. The live rows are the truth; the history records them."""
    return {key: contract_digest(asset) for key, asset in current_tools(deployment).items()}


def _latest_recorded(deployment) -> dict[tuple[str, str], ToolContract]:
    latest: dict[tuple[str, str], ToolContract] = {}
    for row in ToolContract.objects.filter(deployment=deployment).order_by("id"):
        latest[_key(row.tool_kind, row.tool_identifier)] = row
    return latest


def record_tool_contracts(deployment, *, now=None, assets=None) -> dict[tuple[str, str], ToolContract]:
    """Append a :class:`ToolContract` for every tool registration whose contract
    differs from the last one recorded for it (or has none recorded), and return
    the recorded contract in force for every current registration. Idempotent:
    an unchanged contract appends nothing."""
    now = now or timezone.now()
    latest = _latest_recorded(deployment)
    in_force: dict[tuple[str, str], ToolContract] = {}
    for key, asset in current_tools(deployment, assets=assets).items():
        digest = contract_digest(asset)
        row = latest.get(key)
        if row is None or row.digest != digest:
            row = ToolContract.objects.create(
                deployment=deployment,
                asset=asset,
                tool_kind=asset.kind,
                tool_identifier=asset.identifier,
                digest=digest,
                contract=contract_descriptor(asset),
                recorded_at=now,
            )
        in_force[key] = row
    return in_force


def _bind(deployment, tool, *, actor, now, claim=None, workflow=None) -> ToolContractBinding:
    if not is_tool(tool) or tool.deployment_id != deployment.pk:
        raise ValueError("Only a tool, MCP server or skill registered on this deployment carries a contract.")
    key = _key(tool.kind, tool.identifier)
    rows = Asset.objects.filter(deployment=deployment)
    if key not in current_tools(deployment, assets=rows):
        raise ValueError("That tool registration is not in the deployment's graph; nothing can be bound to it.")
    now = now or timezone.now()
    with transaction.atomic():
        # The contract as the registration row stands now, never a copy the
        # caller loaded earlier: binding to a contract already superseded would
        # be an approval of what the tool no longer is.
        contract = record_tool_contracts(deployment, now=now, assets=rows)[key]
        live = ToolContractBinding.objects.select_for_update().filter(
            deployment=deployment, tool_kind=tool.kind, tool_identifier=tool.identifier, released_at__isnull=True
        )
        if claim is not None:
            live = live.filter(claim_fingerprint=claim.fingerprint, workflow__isnull=True)
        else:
            live = live.filter(workflow=workflow)
        current = live.first()
        if current is not None and current.contract_digest == contract.digest:
            return current
        if current is not None:
            current.released_at = now
            current.save(update_fields=["released_at"])
        return ToolContractBinding.objects.create(
            deployment=deployment,
            claim_fingerprint=claim.fingerprint if claim is not None else "",
            claim=claim,
            workflow=workflow,
            tool_kind=tool.kind,
            tool_identifier=tool.identifier,
            contract_digest=contract.digest,
            contract=contract,
            bound_by=actor,
            bound_at=now,
        )


def bind_claim(claim: AssuranceClaim, tool: Asset, *, actor=None, now=None) -> ToolContractBinding:
    """Record that ``claim`` depends on ``tool``, made under the tool's contract in
    force now. Bound to the claim's identity, so every later version of the claim
    carries it. Binding again under the same contract is a no-op; under a new one
    it releases the old binding -- which is how a claim re-established against a
    changed contract stops being held."""
    return _bind(claim.deployment, tool, actor=actor, now=now, claim=claim)


def bind_workflow(workflow: ApprovedWorkflow, tool: Asset, *, actor=None, now=None) -> ToolContractBinding:
    """Record that the approval of ``workflow`` covers ``tool`` under the tool's
    contract in force now. Re-approving under a changed contract is binding again."""
    return _bind(workflow.deployment, tool, actor=actor, now=now, workflow=workflow)


#: The most tools one approved workflow may name. The approved set is read on
#: every assurance answer for the deployment, and each tool is a binding that read
#: carries, so the size is a cost every later request pays.
MAX_TOOLS_PER_WORKFLOW = 100


class ToolApprovalRefused(ValueError):
    """An approval naming a tool it cannot be bound to. ``errors`` maps each
    refused entry's position to why. Nothing the refused call began is kept: it
    raises inside its own transaction."""

    def __init__(self, errors: dict[int, str]):
        self.errors = errors
        super().__init__("; ".join(f"tools[{i}]: {why}" for i, why in sorted(errors.items())))


def approve_workflow_tools(workflow: ApprovedWorkflow, entries, *, actor=None, now=None) -> list[ToolContractBinding]:
    """Make ``entries`` exactly the tools ``workflow``'s approval covers, each bound
    to the contract in force now.

    ``entries``: ``[{"kind", "identifier", "contract_digest"?}]``, shape-checked by
    the caller. This IS the approval of each tool, so:

    - a tool not registered on the deployment is refused: there is no contract to
      approve;
    - an entry that names the ``contract_digest`` it approves is refused when that
      is not the contract in force. Approving a contract the tool no longer has is
      approving what the tool is not -- and it is what a client that read a
      superseded binding back and sent it again would otherwise do: re-approve,
      silently, a change nobody looked at. Without a digest the entry approves the
      contract in force, as :func:`bind_workflow` does;
    - a tool listed twice is refused;
    - a tool bound before and not listed now is released: the approval no longer
      covers it, so there is nothing for its contract to hold.

    A tool listed again under an unchanged contract keeps its binding (no new
    row). Refusals raise :class:`ToolApprovalRefused` inside this call's
    transaction, so a refused approval binds and releases nothing.
    """
    now = now or timezone.now()
    deployment = workflow.deployment
    with transaction.atomic():
        tools = current_tools(deployment, assets=Asset.objects.filter(deployment=deployment))
        errors: dict[int, str] = {}
        resolved: list[tuple[int, Asset, str | None]] = []
        seen: set[tuple[str, str]] = set()
        for i, entry in enumerate(entries):
            key = _key(entry["kind"], entry["identifier"])
            if key in seen:
                errors[i] = f"{entry['kind']} '{entry['identifier']}' is listed twice."
                continue
            seen.add(key)
            asset = tools.get(key)
            if asset is None:
                errors[i] = (
                    f"no {entry['kind']} '{entry['identifier']}' is registered on this deployment, "
                    "so there is no contract to approve."
                )
                continue
            resolved.append((i, asset, entry.get("contract_digest") or None))
        if errors:
            raise ToolApprovalRefused(errors)

        live = ToolContractBinding.objects.select_for_update().filter(workflow=workflow, released_at__isnull=True)
        for binding in live:
            if _key(binding.tool_kind, binding.tool_identifier) not in seen:
                binding.released_at = now
                binding.save(update_fields=["released_at"])

        bound = []
        for i, asset, approved in resolved:
            binding = _bind(deployment, asset, actor=actor, now=now, workflow=workflow)
            # Checked against what was bound, under the lock the bind took, so a
            # contract that moved between the read above and the bind is refused
            # rather than approved unseen.
            if approved is not None and approved != binding.contract_digest:
                errors[i] = (
                    f"approves contract {approved}, but the contract in force for {asset.kind} "
                    f"'{asset.identifier}' is {binding.contract_digest}."
                )
            bound.append(binding)
        if errors:
            raise ToolApprovalRefused(errors)
        return bound


def approved_tools(workflow, digests) -> list[dict]:
    """The tools ``workflow``'s approval covers, as a reader sees them: the contract
    each was approved under, the one in force now (``None`` for a tool no longer
    registered), and whether the approval is SUPERSEDED. ``digests`` is
    :func:`current_digests` for the workflow's deployment, read once by the caller.
    Reads ``workflow.live_tool_bindings`` when the caller prefetched it."""
    live = getattr(workflow, "live_tool_bindings", None)
    if live is None:
        live = list(
            workflow.tool_contract_bindings.filter(released_at__isnull=True).order_by("tool_kind", "tool_identifier")
        )
    out = []
    for binding in live:
        now_digest = digests.get(_key(binding.tool_kind, binding.tool_identifier))
        out.append(
            {
                "kind": binding.tool_kind,
                "identifier": binding.tool_identifier,
                "contract_digest": binding.contract_digest,
                "bound_at": binding.bound_at,
                "current_digest": now_digest,
                "superseded": now_digest != binding.contract_digest,
            }
        )
    return out


def superseded_bindings(deployment, *, digests=None) -> list[ToolContractBinding]:
    """Every live binding on ``deployment`` whose contract is no longer the one in
    force -- the contract moved, or the tool is no longer registered -- each with
    ``current_digest`` set (``None`` for a tool no longer registered). In pk order."""
    # One query, and no join: the decision reads this on every read, and with
    # nothing bound it reads nothing else. A workflow's slug is fetched only for a
    # superseded workflow binding that is reported (:func:`brief`).
    live = list(
        ToolContractBinding.objects.filter(deployment=deployment, released_at__isnull=True).order_by("pk")
    )
    if not live:
        return []
    if digests is None:
        digests = current_digests(deployment)
    out = []
    for binding in live:
        now_digest = digests.get(_key(binding.tool_kind, binding.tool_identifier))
        if now_digest != binding.contract_digest:
            binding.current_digest = now_digest
            out.append(binding)
    return out


def superseded_claim_identities(deployment, *, digests=None) -> frozenset:
    """The claim identities a superseded binding holds."""
    return frozenset(
        b.claim_fingerprint for b in superseded_bindings(deployment, digests=digests) if b.claim_fingerprint
    )


def describe(binding) -> str:
    """The tool and both digests, for a reason a human reads."""
    now_digest = getattr(binding, "current_digest", None)
    return (
        f"{binding.get_tool_kind_display().lower()} '{binding.tool_identifier}' contract changed from "
        f"{binding.contract_digest} to {now_digest or NOT_REGISTERED}"
    )


def reason_for(bindings) -> str:
    """Why a claim bound to these superseded contracts owes a retest."""
    changes = "; ".join(describe(b) for b in bindings)
    return (
        f"Tool contract changed: {changes}. The claim was made under the earlier contract (its schema, "
        "declared effect class and reach); a stable tool name or registry entry does not prove stable "
        "authority, so it needs re-establishing against the contract in force."
    )


def brief(binding) -> dict:
    """A superseded binding, for a decision-support reader."""
    return {
        "subject": "claim" if binding.claim_fingerprint else "workflow",
        "claim_fingerprint": binding.claim_fingerprint or None,
        "workflow": binding.workflow.slug if binding.workflow_id else None,
        "tool_kind": binding.tool_kind,
        "tool_identifier": binding.tool_identifier,
        "bound_digest": binding.contract_digest,
        "current_digest": getattr(binding, "current_digest", None),
    }


def invalidate_superseded(deployment, currents, *, system_fp, actor=None, now=None) -> dict:
    """Invalidate exactly what a tool-contract change superseded.

    ``currents``: the deployment's current claim versions. For every one (not a
    REVOKED withdrawal) whose identity holds a superseded binding: open a retest
    obligation -- unless one is already open for the identity, the existing
    guard -- whose reason names each changed tool and both digests, and move the
    claim to STALE through the existing seam. A superseded workflow approval has
    no claim to retest; it is recorded on the binding and held by the decision
    (:func:`assurance.decision.claim_decision_signal`).

    Each binding records the first time it was found superseded
    (``invalidated_at``/``invalidation_reason``). Where an obligation was already
    open -- the deployment-wide path opened one for the same claim this run -- the
    tool's change is still written on the claim's lifecycle, once.

    Returns ``{invalidated, retests_opened, approvals_superseded, claim_pks}``."""
    from .invalidation import _has_open_requirement, _mark_stale, _open_requirement
    from .claims import Status

    now = now or timezone.now()
    superseded = superseded_bindings(deployment)
    by_identity: dict[str, list[ToolContractBinding]] = {}
    approvals = 0
    for binding in superseded:
        if binding.claim_fingerprint:
            by_identity.setdefault(binding.claim_fingerprint, []).append(binding)
        else:
            approvals += 1
            _record_invalidation(binding, reason_for([binding]), now)

    invalidated, opened, claim_pks = 0, 0, []
    for claim in currents:
        bindings = by_identity.get(claim.fingerprint)
        if not bindings or claim.status == Status.REVOKED:
            continue
        invalidated += 1
        claim_pks.append(claim.pk)
        reason = reason_for(bindings)
        if not _has_open_requirement(deployment, claim):
            _open_requirement(deployment, claim, system_fp=system_fp, now=now, actor=actor, reason=reason)
            opened += 1
        elif any(b.invalidated_at is None for b in bindings):
            ClaimEvent.objects.create(
                claim=claim, from_status=claim.status, to_status=claim.status, actor=actor,
                note=f"Retest already required; also: {reason}",
            )
        for binding in bindings:
            _record_invalidation(binding, reason, now)
        _mark_stale(claim, now, note=f"Tool contract changed; claim invalidated, retest due. {reason}")
    return {
        "invalidated": invalidated,
        "retests_opened": opened,
        "approvals_superseded": approvals,
        "claim_pks": claim_pks,
    }


def _record_invalidation(binding, reason, now) -> None:
    if binding.invalidated_at is not None:
        return
    binding.invalidated_at = now
    binding.invalidation_reason = reason
    binding.save(update_fields=["invalidated_at", "invalidation_reason"])
