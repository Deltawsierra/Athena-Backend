"""The histories this backend records, served read-only to the person (field guide G10).

Three records were kept and never served to an operator:

- every version of each workflow approval (:class:`~assurance.models.ApprovalVersion`,
  noted by :mod:`assurance.approval_history`). Its one reader was Achilles' gate, which
  reads the version in force with a credential of its own (:mod:`assurance.gate_approval`)
  and answers an operator's session 403;
- every tool contract recorded (:class:`~assurance.models.ToolContract`, append-only),
  and every binding of an approval or a claim to one
  (:class:`~assurance.models.ToolContractBinding`), released and invalidated ones
  included. Only the live bindings of approved workflows were served, without their
  ``invalidated_at``/``invalidation_reason``, and the contract in force only for a tool
  some approval binds;
- every accepted change of the deployment's decision
  (:class:`~assurance.models.DecisionTransition`). Only the decision in force and its
  revision were served.

Each function here builds one bounded page of one of them, newest first, for a GET on
:class:`assurance.views.DeploymentViewSet`. The view resolves the deployment through its
own scoped queryset before calling in, so these reads have the same authentication, the
same per-deployment authorization and the same answer for a deployment the person cannot
read as the current-state reads beside them. Nothing here writes, recomputes or repairs a
row, and nothing here is on a stop path.

ABSENT IS ABSENT. A field the record never held is ``None``, never ``0`` and never
``""``: a withdrawn version's digest, the decision before a deployment's first one, a
basis digest nobody supplied, an invalidation that never happened, a binder whose
account is gone, and a tool's binding where none is on record any more (withdrawing an
approval deletes its bindings with it, so an earlier version of an approval withdrawn
since names its tools and digests, and no ``bound_at``).

WHO DECLARED EACH VERSION is served as recorded (``declared_by``, the declarer's
username): the person whose write moved the approval to it. It is ``None`` where nobody
is on record, and nothing here infers one. That covers a version noted with nobody
behind it, one noted before the column existed and a declarer whose account is gone.
Beside it, who bound each tool (``bound_by``) and when (``bound_at``). The
approved-workflows read keeps serving who last declared the approval as it stands
(``approved_by``, ``approved_at``), unchanged.
"""

from __future__ import annotations

from django.db.models import OuterRef, Q, Subquery

from .models import ApprovalVersion, DecisionTransition, ToolContract, ToolContractBinding
from .tool_contract import MAX_TOOLS_PER_WORKFLOW, current_digests


def _page(rows, offset: int, page_size: int) -> tuple[list, int]:
    """One page of an ordered queryset, and how many rows it pages over."""
    total = rows.count()
    return list(rows[offset : offset + page_size]), total


def _envelope(deployment, key: str, items: list, total: int, offset: int, page_size: int) -> dict:
    """The page with the counts the bounded reads of this API serve beside one:
    returned vs recorded, always stated apart, so ``len(items)`` is never read as the
    count."""
    return {
        "deployment": str(deployment.uuid),
        key: items,
        f"{key[:-1]}_count": total,
        "returned": len(items),
        "truncated": offset + len(items) < total,
        "page_size": page_size,
        "offset": offset,
    }


def _username(user_id, user) -> str | None:
    """A user's username, or None when the account is gone (``SET_NULL``) or none was
    recorded."""
    return user.username if user_id else None


# ------------------------------------------------------------------ approval history


def _tool_entry(raw) -> tuple:
    """``(kind, identifier, contract digest)`` of one recorded tool. The history writes
    each as a three-string list; anything else is carried as absent, not guessed at."""
    if isinstance(raw, (list, tuple)) and len(raw) == 3:
        return tuple(str(part) for part in raw)
    return (None, None, None)


def _binding_at(candidates, instant):
    """The binding live at ``instant`` among ``candidates`` (one workflow's bindings of
    one tool under one contract): bound at or before it, not released before it. The
    latest bound wins a tie. None when no binding of it is on record for that instant."""
    live = [
        b
        for b in candidates
        if b.bound_at <= instant and (b.released_at is None or b.released_at >= instant)
    ]
    return max(live, key=lambda b: (b.bound_at, b.id)) if live else None


def approval_history(deployment, *, workflow: str | None, offset: int, page_size: int) -> dict:
    """Every recorded version of the deployment's approvals -- or of one workflow's --
    newest first: ``(in_force_from, id)`` descending, the order the history is read in.

    Each version: its id (the one the gate route names), the workflow, its digest
    (``None`` once withdrawn), when it came into force and until when (the next version
    of the same workflow's ``in_force_from``; ``None`` while no later version is
    recorded), when it was recorded, who declared it (``declared_by``; ``None`` where
    nobody is on record), and every tool it bound with the contract digest each was
    bound under -- and, from the binding live when the version came into force,
    ``bound_at``, ``bound_by``, ``released_at``, ``invalidated_at`` and
    ``invalidation_reason``, all ``None`` where no binding of it is on record.

    Three queries: the count, the page (the next version is a correlated subquery, so it
    is read with it, and the declarer is joined), and the bindings its tools name --
    bounded by the page's own tools.
    """
    rows = ApprovalVersion.objects.filter(deployment=deployment)
    if workflow is not None:
        rows = rows.filter(workflow=workflow)
    later = (
        ApprovalVersion.objects.filter(deployment_id=OuterRef("deployment_id"), workflow=OuterRef("workflow"))
        .filter(
            Q(in_force_from__gt=OuterRef("in_force_from"))
            | Q(in_force_from=OuterRef("in_force_from"), id__gt=OuterRef("id"))
        )
        .order_by("in_force_from", "id")
    )
    page, total = _page(
        rows.annotate(in_force_until=Subquery(later.values("in_force_from")[:1]))
        .select_related("declared_by")
        .order_by("-in_force_from", "-id"),
        offset,
        page_size,
    )

    named = [(version, [_tool_entry(raw) for raw in (version.tools or [])]) for version in page]
    slugs = {version.workflow for version, tools in named if tools}
    digests = {digest for _version, tools in named for (_k, _i, digest) in tools if digest}
    bindings: dict[tuple, list] = {}
    if slugs and digests:
        instants = [version.in_force_from for version, tools in named if tools]
        earliest, latest = min(instants), max(instants)
        # Only bindings that could have been live while a version on this page came
        # into force. Bound syntactically too: each version names at most
        # MAX_TOOLS_PER_WORKFLOW tools, and each tool resolves to the binding live then
        # or, for the oldest version of a workflow on the page, the one before it.
        candidates = (
            ToolContractBinding.objects.filter(
                deployment=deployment,
                workflow__deployment=deployment,
                workflow__slug__in=slugs,
                contract_digest__in=digests,
                bound_at__lte=latest,
            )
            .filter(Q(released_at__isnull=True) | Q(released_at__gte=earliest))
            .select_related("workflow", "bound_by")
            .order_by("bound_at", "id")[: 2 * page_size * MAX_TOOLS_PER_WORKFLOW]
        )
        for binding in candidates:
            key = (binding.workflow.slug, binding.tool_kind, binding.tool_identifier, binding.contract_digest)
            bindings.setdefault(key, []).append(binding)

    versions = []
    for version, tools in named:
        served_tools = []
        for kind, identifier, digest in tools:
            binding = _binding_at(bindings.get((version.workflow, kind, identifier, digest), ()), version.in_force_from)
            served_tools.append(
                {
                    "kind": kind,
                    "identifier": identifier,
                    "contract_digest": digest,
                    "bound_at": binding.bound_at if binding else None,
                    "bound_by": _username(binding.bound_by_id, binding.bound_by) if binding else None,
                    "released_at": binding.released_at if binding else None,
                    "invalidated_at": binding.invalidated_at if binding else None,
                    "invalidation_reason": (binding.invalidation_reason or None) if binding else None,
                }
            )
        versions.append(
            {
                "version": str(version.id),
                "workflow": version.workflow,
                "digest": version.digest or None,
                "withdrawn": not version.digest,
                "in_force_from": version.in_force_from,
                "in_force_until": version.in_force_until,
                "recorded_at": version.recorded_at,
                "declared_by": _username(version.declared_by_id, version.declared_by),
                "tools": served_tools,
            }
        )
    return {"workflow": workflow, **_envelope(deployment, "versions", versions, total, offset, page_size)}


# --------------------------------------------------------------- tool contract history


def tool_contract_history(
    deployment, *, kind: str | None, identifier: str | None, offset: int, page_size: int
) -> dict:
    """Every tool contract recorded for the deployment -- or for one registration --
    newest first, in the order they were recorded (``id`` descending: the order the
    history decides supersession in).

    Each contract: the registration it was read off, its digest, the canonical
    descriptor as recorded, when it was recorded, when the next contract of the same
    registration was recorded (``superseded_at``; ``None`` while none later is), the
    registration's contract in force now (``current_digest``, read off the registration
    rows as every other reader does; ``None`` for a tool no longer registered), and
    whether this row is that contract (``in_force``: the newest recorded for its
    registration, with the digest in force). A tool no approval binds is here like any
    other.

    Three queries and the registration rows: the count, the page with its successor's
    ``recorded_at``, and the contracts in force.
    """
    rows = ToolContract.objects.filter(deployment=deployment)
    if kind is not None:
        rows = rows.filter(tool_kind=kind)
    if identifier is not None:
        rows = rows.filter(tool_identifier=identifier)
    later = ToolContract.objects.filter(
        deployment_id=OuterRef("deployment_id"),
        tool_kind=OuterRef("tool_kind"),
        tool_identifier=OuterRef("tool_identifier"),
        id__gt=OuterRef("id"),
    ).order_by("id")
    page, total = _page(
        rows.annotate(superseded_at=Subquery(later.values("recorded_at")[:1])).order_by("-id"),
        offset,
        page_size,
    )
    digests = current_digests(deployment) if page else {}
    contracts = []
    for row in page:
        current = digests.get((str(row.tool_kind), str(row.tool_identifier)))
        contracts.append(
            {
                "kind": row.tool_kind,
                "identifier": row.tool_identifier,
                "digest": row.digest,
                "contract": row.contract,
                "recorded_at": row.recorded_at,
                "superseded_at": row.superseded_at,
                "current_digest": current,
                "in_force": row.superseded_at is None and current == row.digest,
            }
        )
    return {
        "kind": kind,
        "identifier": identifier,
        **_envelope(deployment, "contracts", contracts, total, offset, page_size),
    }


def tool_contract_bindings(
    deployment, *, kind: str | None, identifier: str | None, offset: int, page_size: int
) -> dict:
    """Every binding of an approval or a claim to a tool contract on the deployment --
    or on one registration -- live, released and invalidated alike, newest first
    (``id`` descending).

    Each binding: what it binds (``subject``: ``workflow`` with its slug, or ``claim``
    with the claim identity), the tool, the contract digest it was bound under, the one
    in force now (``None`` for a tool no longer registered), ``live`` (not released) and,
    for a live binding, ``superseded`` -- the contract moved or the tool left, decided
    live exactly as :func:`assurance.tool_contract.superseded_bindings` decides it; a
    released binding holds nothing, so it is ``None`` there. Then who bound it and when,
    when it was released, and when the invalidation engine first found it superseded,
    with why (``invalidated_at``, ``invalidation_reason``; ``None`` when it never has).

    Two queries and the registration rows: the count, the page with its workflow and
    binder, and the contracts in force.
    """
    rows = ToolContractBinding.objects.filter(deployment=deployment)
    if kind is not None:
        rows = rows.filter(tool_kind=kind)
    if identifier is not None:
        rows = rows.filter(tool_identifier=identifier)
    page, total = _page(rows.select_related("workflow", "bound_by").order_by("-id"), offset, page_size)
    digests = current_digests(deployment) if page else {}
    served = []
    for binding in page:
        current = digests.get((str(binding.tool_kind), str(binding.tool_identifier)))
        live = binding.released_at is None
        served.append(
            {
                "subject": "claim" if binding.claim_fingerprint else "workflow",
                "workflow": binding.workflow.slug if binding.workflow_id else None,
                "claim_fingerprint": binding.claim_fingerprint or None,
                "kind": binding.tool_kind,
                "identifier": binding.tool_identifier,
                "contract_digest": binding.contract_digest,
                "current_digest": current,
                "live": live,
                "superseded": (current != binding.contract_digest) if live else None,
                "bound_at": binding.bound_at,
                "bound_by": _username(binding.bound_by_id, binding.bound_by),
                "released_at": binding.released_at,
                "invalidated_at": binding.invalidated_at,
                "invalidation_reason": binding.invalidation_reason or None,
            }
        )
    return {
        "kind": kind,
        "identifier": identifier,
        **_envelope(deployment, "bindings", served, total, offset, page_size),
    }


# -------------------------------------------------------------------- decision history


def decision_history(deployment, *, offset: int, page_size: int) -> dict:
    """Every accepted change of the deployment's decision, newest first by revision --
    the transition log a downstream consumer drains (:func:`assurance.revision.
    transitions_since`), read as it stands. Each change: its revision, the decision it
    moved from (``None``: there was none before) and to (``None``: none after), what the
    decision was computed from (``basis_digest``; ``None`` when the writer supplied
    none), when it was accepted (``created_at``) and when a downstream consumer
    confirmed it (``delivered_at``; ``None``: not yet).

    The log only: nothing here reconciles the stored decision with it, recomputes it or
    repairs a row behind it. The decision in force is decision-support's to publish.

    Two queries: the count and the page.
    """
    page, total = _page(DecisionTransition.objects.filter(deployment=deployment).order_by("-revision"), offset, page_size)
    transitions = [
        {
            "revision": t.revision,
            "from_decision": t.from_decision or None,
            "to_decision": t.to_decision or None,
            "basis_digest": t.basis_digest or None,
            "created_at": t.created_at,
            "delivered_at": t.delivered_at,
        }
        for t in page
    ]
    return _envelope(deployment, "transitions", transitions, total, offset, page_size)


__all__ = ["approval_history", "decision_history", "tool_contract_bindings", "tool_contract_history"]
