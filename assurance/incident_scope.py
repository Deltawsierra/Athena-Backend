"""An incident's scope, versioned (SPINE SP-3): what is believed affected, and every correction.

The incident is a :class:`~assurance.models.Finding` (:mod:`assurance.incident`). Its scope
is its :class:`~assurance.models.IncidentScopeRevision` rows, oldest first: one numbered
revision per change, the newest current. A scope changes during an investigation (the
handbook's R15, the vendor modem the first scope left out; the infrastructure study's T01,
an undocumented route), and the rule the studies set is ``mythos_core.evidence_record``'s:
"Version and supersede them when stronger evidence arrives. Do not erase the earlier
assessment." So a revision is never edited or deleted (:mod:`assurance.append_only`); a
change is the next revision, which names the one it ``supersedes``, and every earlier one
stays readable.

**What a revision holds**, each part required:

=============  ==================================================================
``items``      what is in scope, each ``{"kind", "ref"}`` resolved in the finding's
               own deployment and refused (``unknown_link``) when it is another's
               or does not exist: ``asset`` (an ``Asset``, by uuid; its own
               ``Asset.Kind`` is kept beside it) or ``workflow`` (an
               ``ApprovedWorkflow``, by slug). At least one.
``reason``     why the scope is this, in the declarer's words.
``evidence``   the ``Evidence`` of the deployment's findings it rests on. At least
               one (``evidence_record``'s ``evidence_required``).
``declared_by``  the signed-in person who declared it, never a posted field.
=============  ==================================================================

The kinds are this backend's own records, as the recovery record's witnesses are
(``evidence``, ``permit``, ``receipt``): Mythos-Core holds no closed set of scope item
kinds, and none is invented here. A route has no record of its own in this backend, so a
route is in scope as the assets on it.

**What a recovery reads of it** (:func:`holds`, :func:`since`, :func:`removed`). A
recovered state holds for the scope its step was derived under
(:mod:`assurance.recovery_record`). Each thing below holds a recovered state back, named:

- ``scope:not_declared``: the step was derived with no revision on record, or names one
  that is not on record. No declared scope is unknown, never ok.
- ``scope:revision:<n>:added:<kind>:<ref>``: the item is in the current scope, revision
  ``n`` (after the first) added it and it has been in scope ever since, and either ``n``
  is later than the step's revision or the step links nothing that names the item. An
  item removed and added again counts from the revision that added it again.
- ``scope:unreadable``: a revision's items cannot be read. Unreadable is caution.

**A narrowing ends the hold for the item it removes, openly.** The hold for an added item
stands only while the item is in the current scope and nothing names it. An item a
revision added and a later one removed is no longer a gap; it is listed with the record
and with every step derived after it (:func:`removed`: both revision numbers, who removed
it and why). A revision that only removes items takes no recovered state away by itself.
A revision that removes an item names who declared it (``declared_by_required``), as every
revision states why in one printable line. The first declared scope's items are not tied
one by one: only items added later are.

Reads and writes only this record; nothing a stop or the decision reads.
"""

from __future__ import annotations

import re
import uuid

from django.db import IntegrityError, transaction
from django.utils import timezone

ASSET = "asset"
WORKFLOW = "workflow"
#: Each kind of item, by the record of the finding's deployment it resolves to.
KINDS = (ASSET, WORKFLOW)

NOT_DECLARED = "scope:not_declared"
UNREADABLE = "scope:unreadable"

POSTED = ("items", "reason", "evidence")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SLUG = re.compile(r"[-a-zA-Z0-9_]{1,200}")
_MOST = 100
_REASON_MOST = 500


class ScopeRefused(ValueError):
    """A scope revision refused, with the code of the rule it broke."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------- what a revision holds


def _reason(value) -> str:
    """Why, as prose: exactly a string, not blank, ONE printable line (no line break, no
    control or format character, so nothing hides or reorders text), at most
    :data:`_REASON_MOST` characters. The refusal never repeats what it refused."""
    if type(value) is not str or not value.strip() or not value.isprintable() or len(value) > _REASON_MOST:
        raise ScopeRefused(
            "malformed", f"a scope revision states why, in one printable line of at most {_REASON_MOST} characters"
        )
    return value


def _posted(value) -> list[tuple[str, str]]:
    """The ``(kind, ref)`` of each posted item, each named once."""
    if not isinstance(value, list) or len(value) > _MOST:
        raise ScopeRefused("malformed", f"items is a list of at most {_MOST}")
    named = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"kind", "ref"}:
            raise ScopeRefused("malformed", "each item is {kind, ref} and nothing else")
        kind, ref = item["kind"], item["ref"]
        if type(kind) is not str or kind not in KINDS:
            raise ScopeRefused("malformed", f"an item's kind is one of {list(KINDS)}")
        if type(ref) is not str or not (_UUID if kind == ASSET else _SLUG).fullmatch(ref):
            raise ScopeRefused("malformed", f"a {kind}'s ref is its {'uuid' if kind == ASSET else 'slug'}")
        named.append((kind, ref))
    if len(set(named)) != len(named):
        raise ScopeRefused("malformed", "items names each one once")
    return named


def resolve_items(finding, value) -> list[dict]:
    """The posted items, each resolved in ``finding``'s own deployment. Refuses one that
    is another deployment's exactly as one that does not exist, and a revision of none."""
    from .models import ApprovedWorkflow, Asset

    named = _posted(value)
    if not named:
        raise ScopeRefused("items_required", "a scope revision names at least one item in scope")
    deployment_id = finding.deployment_id
    assets = {
        str(a.uuid): a.kind
        for a in Asset.objects.filter(
            deployment_id=deployment_id, uuid__in=[uuid.UUID(ref) for kind, ref in named if kind == ASSET]
        ).only("uuid", "kind")
    }
    workflows = set(
        ApprovedWorkflow.objects.filter(
            deployment_id=deployment_id, slug__in=[ref for kind, ref in named if kind == WORKFLOW]
        ).values_list("slug", flat=True)
    )
    items = []
    for kind, ref in named:
        if kind == ASSET:
            if ref not in assets:
                raise ScopeRefused("unknown_link", f"asset {ref} is not an asset of this deployment")
            items.append({"kind": ASSET, "ref": ref, "asset_kind": assets[ref]})
        else:
            if ref not in workflows:
                raise ScopeRefused("unknown_link", f"workflow {ref} is not an approved workflow of this deployment")
            items.append({"kind": WORKFLOW, "ref": ref})
    return items


def resolve_evidence(finding, value) -> list[dict]:
    """The evidence a revision rests on, each of the deployment's own findings, as the
    recovery record links it. Refuses none at all."""
    from .models import Evidence

    if not isinstance(value, list) or len(value) > _MOST:
        raise ScopeRefused("malformed", f"evidence is a list of at most {_MOST}")
    for one in value:
        if type(one) is not str or not _UUID.fullmatch(one):
            raise ScopeRefused("malformed", "each of evidence is an evidence uuid")
    if len(set(value)) != len(value):
        raise ScopeRefused("malformed", "evidence names each one once")
    if not value:
        raise ScopeRefused("evidence_required", "a scope revision names the evidence it rests on")
    found = {
        str(e.uuid): e.classification
        for e in Evidence.objects.filter(
            uuid__in=[uuid.UUID(one) for one in value], finding__deployment_id=finding.deployment_id
        ).only("uuid", "classification")
    }
    for one in value:
        if one not in found:
            raise ScopeRefused("unknown_link", f"evidence {one} is not evidence of this deployment")
    return [{"uuid": one, "classification": found[one]} for one in value]


def _keys(items) -> list[tuple[str, str]] | None:
    """Each stored item's ``(kind, ref)``, or None when the items cannot be read."""
    try:
        keys = [(item["kind"], item["ref"]) for item in items]
    except (KeyError, TypeError):
        return None
    return keys if all(type(kind) is str and type(ref) is str for kind, ref in keys) else None


def check(row) -> None:
    """Refuse ``row`` (unsaved) unless it is the next revision of its incident's scope:
    it supersedes the current one, changes it, and every item and piece of evidence it
    stores is what resolves in the finding's own deployment now."""
    from .models import IncidentScopeRevision

    latest = IncidentScopeRevision.objects.filter(finding_id=row.finding_id).order_by("-revision").first()
    current = None if latest is None else latest.revision
    number = row.revision
    if not isinstance(number, int) or number < 1 or row.supersedes != (None if number == 1 else number - 1):
        raise ScopeRefused("bad_supersedes", "revision 1 supersedes none; each later one the revision before it")
    if row.supersedes != current:
        standing = "no revision is on record" if current is None else f"revision {current} is current"
        raise ScopeRefused("not_current", f"{standing}: the next revision supersedes that, not {row.supersedes}")
    _reason(row.reason)
    keys = _keys(row.items) if isinstance(row.items, list) else None
    if keys is None or row.items != resolve_items(row.finding, [{"kind": kind, "ref": ref} for kind, ref in keys]):
        raise ScopeRefused("malformed", "a scope revision's items are those that resolve in its deployment")
    try:
        rests_on = [one["uuid"] for one in row.evidence]
    except (KeyError, TypeError):
        rests_on = None
    if rests_on is None or row.evidence != resolve_evidence(row.finding, rests_on):
        raise ScopeRefused("malformed", "a scope revision's evidence is the deployment's own")
    if latest is not None and row.declared_by_id is None and set(_keys(latest.items) or ()) - set(keys):
        raise ScopeRefused("declared_by_required", "a revision that removes an item names who declared it")
    if latest is not None and set(_keys(latest.items) or ()) == set(keys):
        raise ScopeRefused(
            "nothing_changed", f"nothing changed: revision {current} already holds exactly these items"
        )


def declare(finding, *, by=None, body=None):
    """Record the next revision of ``finding``'s scope, declared by ``by``, and return it.
    ``body`` is ``{"items": [{kind, ref}], "reason": <why>, "evidence": [<uuid>]}`` and
    nothing else. Refused, with nothing recorded, when a part is missing, an item or a
    piece of evidence is not the deployment's own, or nothing changes."""
    from .models import IncidentScopeRevision

    if not isinstance(body, dict):
        raise ScopeRefused("malformed", "a scope revision is posted as an object")
    extra = sorted(str(key) for key in body if key not in POSTED)
    if extra:
        raise ScopeRefused(
            "not_posted",
            f"{extra}: not what a scope revision takes. Its number, the revision it supersedes, who declared it "
            "and when are recorded, never posted",
        )
    missing = [key for key in POSTED if key not in body]
    if missing:
        raise ScopeRefused("malformed", f"a scope revision names its items, its reason and its evidence: {missing} missing")
    items = resolve_items(finding, body["items"])
    evidence = resolve_evidence(finding, body["evidence"])
    latest = IncidentScopeRevision.objects.filter(finding_id=finding.pk).order_by("-revision").first()
    row = IncidentScopeRevision(
        finding=finding,
        revision=1 if latest is None else latest.revision + 1,
        supersedes=None if latest is None else latest.revision,
        items=items, reason=_reason(body["reason"]), evidence=evidence, declared_by=by, declared_at=timezone.now(),
    )
    try:
        with transaction.atomic():
            row.save()
    except IntegrityError:
        raise ScopeRefused("raced", "another revision of this scope was declared at the same time") from None
    return row


# --------------------------------------------------------- what a recovery reads of it


def gap(revision: int, kind: str, ref: str) -> str:
    """The name of the gap an added item leaves: the revision that added it, and the item."""
    return f"scope:revision:{revision}:added:{kind}:{ref}"


def _walk(revisions, upto=None):
    """``(since, removed)`` up to revision ``upto`` (the newest when None), or None when a
    revision's items cannot be read. See :func:`since` and :func:`removed`."""
    held, gone, first = {}, [], None
    for row in revisions:
        if upto is not None and row.revision > upto:
            break
        keys = _keys(row.items)
        if keys is None:
            return None
        first = row.revision if first is None else first
        gone += [
            {
                "kind": kind, "ref": ref, "added": added, "removed": row.revision,
                "removed_by": row.declared_by.username if getattr(row, "declared_by_id", None) else None,
                "reason": getattr(row, "reason", ""),
            }
            for (kind, ref), added in held.items() if (kind, ref) not in keys and added > first
        ]
        held = {key: held.get(key, row.revision) for key in keys}
    return held, gone


def since(revisions, upto=None) -> dict | None:
    """For every item in scope as of revision ``upto`` (the newest when None), by
    ``(kind, ref)``: the revision since which it has been in scope without a break. An
    item removed and added again counts from when it was added again. None when a
    revision's items cannot be read. Pure."""
    walked = _walk(revisions, upto)
    return None if walked is None else walked[0]


def removed(revisions, upto=None) -> list[dict] | None:
    """Every item a revision after the first added and a later one removed, up to revision
    ``upto``: its kind and ref, both revision numbers, who removed it and why. Disclosed
    with every step derived after it; not a gap. None when a revision's items cannot be
    read. Pure."""
    walked = _walk(revisions, upto)
    return None if walked is None else walked[1]


def holds(taken_under, revisions) -> list[str]:
    """Each thing about an incident's scope that holds a recovered state back, named, for
    a step derived under revision ``taken_under`` (None: none was declared), given every
    revision of the incident, oldest first: no declared scope, an unreadable one, or each
    item a LATER revision added that is in scope now. A later revision that removes the
    item ends that hold, and a revision that only removes items holds nothing back.
    Empty when the scope the step was derived under still covers the current one. Pure."""
    if taken_under is None:
        return [NOT_DECLARED]
    standing = since(revisions)
    if standing is None:
        return [UNREADABLE]
    if taken_under not in {row.revision for row in revisions}:
        return [NOT_DECLARED]
    return [gap(added, kind, ref) for (kind, ref), added in standing.items() if added > taken_under]


def current_of(revisions) -> int | None:
    """The number of the current revision among ``revisions``, oldest first; None when
    none is declared."""
    return revisions[-1].revision if revisions else None


def revisions_of(finding_ids) -> dict:
    """Every scope revision of each finding in ``finding_ids``, oldest first, by finding
    id. One query."""
    from .models import IncidentScopeRevision

    rows = (
        IncidentScopeRevision.objects.filter(finding_id__in=finding_ids)
        .select_related("declared_by")
        .order_by("finding_id", "revision")
    )
    revisions: dict = {}
    for row in rows:
        revisions.setdefault(row.finding_id, []).append(row)
    return revisions


# ------------------------------------------------------------------ the reads


def served(row, before=None, *, current) -> dict:
    """One revision as its read serves it: what it holds as recorded, what it added to
    and removed from the revision ``before`` it (everything it holds is added when there
    is none), whether it is the current one, and who declared it (``None`` when nobody
    is on record)."""
    now, was = _keys(row.items) or [], (_keys(before.items) or []) if before is not None else []
    return {
        "ref": str(row.uuid),
        "revision": row.revision,
        "supersedes": row.supersedes,
        "current": row.revision == current,
        "items": row.items,
        "added": [{"kind": kind, "ref": ref} for kind, ref in now if (kind, ref) not in was],
        "removed": [{"kind": kind, "ref": ref} for kind, ref in was if (kind, ref) not in now],
        "reason": row.reason,
        "evidence": row.evidence,
        "declared_by": row.declared_by.username if row.declared_by_id else None,
        "declared_at": row.declared_at.isoformat(),
    }


def finding_scope(finding) -> dict:
    """One incident's scope: every revision, oldest first, and the number of the current
    one (``None`` when no scope is declared)."""
    revisions = revisions_of([finding.pk]).get(finding.pk, [])
    current = current_of(revisions)
    return {
        "deployment": str(finding.deployment.uuid),
        "finding": str(finding.uuid),
        "current": current,
        "revisions": [
            served(row, revisions[index - 1] if index else None, current=current) for index, row in enumerate(revisions)
        ],
    }
