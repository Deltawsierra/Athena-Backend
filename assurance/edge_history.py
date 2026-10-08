"""Which graph edges were in force when: the history ``through_identity``, ``performs``
and reach are read against, as of dispatch.

Part 5 of the owner's 7 Oct decision read an authority chain's ``under_policy`` and
``invokes`` AS OF DISPATCH, against the approval, contracts and route in force at the
instant the effect's dispatch left (:mod:`assurance.approval_history`). The graph hops
were still read LIVE: the graph (:func:`assurance.authority_chain_records.load_graph`)
is computed from the deployment's :class:`assurance.models.Asset` rows as they stand
now, and nothing kept what it was. So an identity, action or reach edge changed after
an effect unproved that effect, and an effect made through an edge removed before its
dispatch read proven once the edge was restored.

This module keeps that history -- :class:`assurance.models.AuthorityEdgeVersion`,
append-only -- for exactly the edges those hops read
(:func:`assurance.authority_chain.graph_edges`): an agent's identity, a component's
permission, a principal's reach to a tool. Each edge's appearance and disappearance is
a row, with the instant the platform noticed it; one ``begun`` row says from when the
history covers the deployment.

WHEN AN EDGE IS NOTED (:func:`note_edges`). In the same transaction as every write that
can move one: an asset saved (with a field the graph reads) or deleted
(:mod:`assurance.signals`), and the asset reconciliation of a scan, whose writes are
partly bulk and which no signal sees whole -- it is noted once, at its end
(:func:`edges_noted_once`, :func:`assurance.assets.derive_assets`). And again at every
decision refresh (:func:`note_edges_quietly`, beside the approvals' note), so a write
no signal saw -- a ``QuerySet.update``, a data migration -- is noted too.
``noticed_at`` is when the platform NOTICED: at or after the change, never when the
customer made it. A dispatch before the history began reads as one whose state nothing
recorded, never as one through no edge, and never live.

Never on a stop path. No stop writes an asset, and the refresh's note never raises: a
failure is logged and the next note takes it.
"""

from __future__ import annotations

import contextlib
import contextvars
import copy
import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

#: The kind of the one row per deployment that says from when its edge history
#: begins. It carries no edge.
BEGUN = "begun"

#: The deployments whose edges are noted once, after a bulk writer finishes
#: (:func:`edges_noted_once`): an asset write inside it notes nothing by itself.
_NOTED_ONCE: contextvars.ContextVar[frozenset] = contextvars.ContextVar(
    "assurance_edges_noted_once", default=frozenset()
)


def edges_now(deployment) -> frozenset[tuple[str, str, str]]:
    """Every edge ``through_identity``, ``performs`` and reach read, as the graph of
    ``deployment`` stands now: ``(kind, source, target)``. The assets are read once
    (with their providers), for every reader of the graph: this runs in the
    transaction of the write it notes."""
    from django.db.models import prefetch_related_objects

    from .authority_chain import graph_edges
    from .authority_chain_records import load_graph

    # A copy, so a caller's own prefetched assets -- the graph as it was when it read
    # them, not as the write being noted left it -- are neither read nor replaced.
    fresh = copy.copy(deployment)
    fresh._prefetched_objects_cache = {}
    prefetch_related_objects([fresh], "assets__provider")
    return graph_edges(load_graph(fresh, coverage=False))


def _latest(deployment) -> tuple[bool, dict[tuple[str, str, str], tuple[bool, object]]]:
    """Whether the history of ``deployment`` has begun, and each edge's latest change:
    ``(kind, source, target) -> (in force, noticed at)``. One query."""
    from .models import AuthorityEdgeVersion

    begun = False
    latest: dict[tuple[str, str, str], tuple[bool, object]] = {}
    rows = (
        AuthorityEdgeVersion.objects.filter(deployment=deployment)
        .order_by("noticed_at", "id")
        .values_list("kind", "source", "target", "in_force", "noticed_at")
    )
    for kind, source, target, in_force, noticed_at in rows:
        if kind == BEGUN:
            begun = True
            continue
        latest[(kind, source, target)] = (in_force, noticed_at)
    return begun, latest


def note_edges(deployment, *, now=None) -> list:
    """Append an :class:`~assurance.models.AuthorityEdgeVersion` for every edge of
    ``deployment`` that came into force or went out of it since its last recorded
    change, and the ``begun`` row the first time. Idempotent: an unchanged graph appends
    nothing. Returns the rows appended. Runs in the caller's transaction, so an asset
    write and its history commit together.

    Inside :func:`edges_noted_once` for this deployment, notes nothing: the bulk writer
    notes once, when it is done."""
    from .models import AuthorityEdgeVersion

    if deployment.pk in _NOTED_ONCE.get():
        return []
    now = now or timezone.now()
    current = edges_now(deployment)
    begun, latest = _latest(deployment)
    rows = []
    if not begun:
        rows.append(
            AuthorityEdgeVersion(
                deployment=deployment, kind=BEGUN, source="", target="", in_force=True, noticed_at=now
            )
        )
    for key in sorted(current | {key for key, (in_force, _) in latest.items() if in_force}):
        in_force = key in current
        last = latest.get(key)
        if last is None and not in_force:
            continue
        if last is not None and last[0] == in_force:
            continue
        # Never before the change it follows: a clock that stepped back must not place
        # this change before the last one in the history.
        instant = now if last is None or now >= last[1] else last[1]
        kind, source, target = key
        rows.append(
            AuthorityEdgeVersion(
                deployment=deployment, kind=kind, source=source, target=target, in_force=in_force, noticed_at=instant
            )
        )
    if rows:
        AuthorityEdgeVersion.objects.bulk_create(rows)
    return rows


def note_edges_quietly(deployment, *, now=None) -> None:
    """:func:`note_edges`, for the decision refresh, which must not fail for it. A
    failure is logged and rolled back to before the note, and costs only that: the next
    note sees the change instead, and a late note only ever leaves a dispatch before it
    reading the edge as it was. Never raises."""
    try:
        with transaction.atomic():
            note_edges(deployment, now=now)
    except Exception:
        logger.exception(
            "the graph edges of deployment %s were not noted; the next asset write or "
            "decision refresh notes them instead",
            deployment.pk,
        )


@contextlib.contextmanager
def edges_noted_once(deployment):
    """While this runs, an asset write of ``deployment`` notes no edge by itself; when
    it ends without raising, the edges are noted once, in the caller's transaction.
    For a writer that writes many assets, some in bulk where no signal sees them
    (:func:`assurance.assets.derive_assets`). If it raises, its transaction is the
    caller's to roll back, and the next note -- a write, or the decision refresh --
    takes whatever stood."""
    token = _NOTED_ONCE.set(_NOTED_ONCE.get() | {deployment.pk})
    try:
        yield
    finally:
        _NOTED_ONCE.reset(token)
    note_edges(deployment)


def history(deployment) -> tuple[object, dict[tuple[str, str, str], tuple]]:
    """``(begun, history)``: from when the edge history of ``deployment`` covers it
    (``None``: it never began), and every recorded change of every edge, oldest first,
    by ``(kind, source, target)``, as :class:`assurance.authority_chain.EdgeVersion`.
    One query."""
    from .authority_chain import EdgeVersion
    from .models import AuthorityEdgeVersion

    begun = None
    found: dict[tuple[str, str, str], list] = {}
    rows = (
        AuthorityEdgeVersion.objects.filter(deployment=deployment)
        .order_by("noticed_at", "id")
        .values_list("id", "kind", "source", "target", "in_force", "noticed_at")
    )
    for pk, kind, source, target, in_force, noticed_at in rows:
        if kind == BEGUN:
            begun = noticed_at if begun is None else min(begun, noticed_at)
            continue
        found.setdefault((kind, source, target), []).append(
            EdgeVersion(noticed_at=noticed_at, in_force=in_force, record=str(pk))
        )
    return begun, {key: tuple(versions) for key, versions in found.items()}
