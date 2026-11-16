"""An incident's scope is versioned, and no recovery outlives the scope it was taken under (SPINE SP-3).

The recovery record (SP-1) derived an incident's state from its witnesses and had no
notion of its scope: what is believed affected. A scope changes during an investigation
(the handbook's R15, the infrastructure study's T01: a backup route found late). A
recovery accepted before the route was found still read ``recovery_accepted`` and
``PASS``. :mod:`assurance.incident_scope` keeps the scope as numbered, append-only
revisions, and :mod:`assurance.recovery_record` holds each step to the revision it was
derived under:

- a revision is one change: its items (each resolved in the finding's own deployment, and
  refused when it is another's), why, the evidence it rests on and who declared it. The
  earlier revision stays as recorded; nothing is edited or deleted;
- with no declared scope no step reaches a recovered state: it names ``scope:not_declared``
  and reads ``AUDIT_INCOMPLETE``. No declared scope is unknown, never ok;
- when a later revision adds an item, a recovered step taken before it is no longer read
  as recovered: the read names the revision and the item among the gaps and its release
  is ``AUDIT_INCOMPLETE``;
- an added item stays an open gap until a step recorded under that revision links
  evidence that names it (evidence of a finding of the same deployment attached to that
  asset). An empty step, or one whose evidence names none of the added items, moves
  nothing; one item's evidence covers no other; another deployment's covers none;
- a revision that only removes items never advances a state by itself;
- rows from before this change are not rewritten, and read ``scope:not_declared``.

The SAFETY RULE: nothing here is on a stop path. No stop package imports either module,
and the last test makes every function of both fail and drives the stops: each is served
as before.

On master there is no scope, and this file does not import there.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone
from mythos_core import evidence_record
from mythos_core import outcome as oc
from mythos_core import status as st
from rest_framework.test import APIClient

from assurance import incident_scope as scope
from assurance import recovery_record as rr
from assurance import signals
from assurance.models import (
    ApprovedWorkflow,
    Deployment,
    Evidence,
    Finding,
    IncidentScopeRevision,
    IncidentScopeRewriteRefused,
    RecoveryRecord,
)
from safety import degraded, stops
from tests import incident_scopes as scopes
from tests.incident_scopes import declare as declare_scope
from tests.signed_chains import record_reconciliation, record_signed
from tests.test_a_recovery_record_is_derived_from_its_witnesses import (
    COVERED,
    T0,
    T1,
    WF,
    _history,
    _incident,
    _permit,
    _repaired_and_tested,
    _states,
    _until,
)

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
NOT_DECLARED = "scope:not_declared"


def _revisions(finding):
    return list(IncidentScopeRevision._base_manager.filter(finding=finding).order_by("revision").values())


def _added(number, record) -> str:
    """The gap that names ``record`` as an item revision ``number`` added."""
    item = scopes.item(record)
    return f"scope:revision:{number}:added:{item['kind']}:{item['ref']}"


def _read(finding):
    return rr.finding_record(finding)


def _standing(read) -> list[tuple[str, str]]:
    """Every (state, release) a read shows as standing: each step's, and the current one."""
    return [(step["state"], step["release"]) for step in read["steps"]] + [
        (read["current"]["state"], read["current"]["release"])
    ]


def _accepted(finding, *records):
    """``finding``'s recovery, accepted by the owner under its first scope revision."""
    declare_scope(finding, *records)
    _repaired_and_tested(finding)
    steps = rr.record(finding, by=finding.deployment.owner, body={"coverage": COVERED}, accept_until=_until())
    assert (steps[-1].state, steps[-1].release, steps[-1].scope_revision) == (st.RECOVERY_ACCEPTED, st.PASS, 1)
    return steps


def _restored(finding, *records):
    """``finding``'s recovery, restored with restrictions under its first scope revision."""
    declare_scope(finding, *records)
    _repaired_and_tested(finding)
    dep = finding.deployment
    permit = _permit(dep)
    receipt = record_reconciliation(dep, WF, permit, "applied").receipt_id
    body = {"permits": [permit], "receipts": [receipt], "restrictions": ["refunds-manual-only"], "coverage": COVERED}
    steps = rr.record(finding, body=body)
    assert (steps[-1].state, steps[-1].scope_revision) == (st.RESTORED_WITH_RESTRICTIONS, 1)
    return steps


# ------------------------------------------------- the scope: numbered, append-only


def test_a_scope_is_numbered_revisions_and_every_earlier_one_stays_as_recorded():
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary, backup = scopes.asset(dep, "primary-route"), scopes.asset(dep, "backup-route")
    refund = ApprovedWorkflow.objects.create(deployment=dep, slug="refund", name="Refund")
    first_evidence = scopes.evidence_of(finding)

    first = declare_scope(finding, primary, refund, by=owner, reason="what the scan reached", evidence=first_evidence)
    kept = _revisions(finding)
    second = declare_scope(finding, primary, refund, backup, reason="a backup route in the firewall export")
    # A revision that removes an item names who declared it, as every revision states why.
    with pytest.raises(scope.ScopeRefused) as refused:
        declare_scope(finding, primary, backup, reason="the refund workflow was never called")
    assert refused.value.code == "declared_by_required"
    third = declare_scope(finding, primary, backup, by=owner, reason="the refund workflow was never called")

    assert [(r.revision, r.supersedes) for r in (first, second, third)] == [(1, None), (2, 1), (3, 2)]
    assert first.items == [
        {"kind": "asset", "ref": str(primary.uuid), "asset_kind": "gateway"},
        {"kind": "workflow", "ref": "refund"},
    ]
    assert (first.reason, first.declared_by) == ("what the scan reached", owner)
    assert first.evidence == [{"uuid": str(first_evidence.uuid), "classification": "technically_verified"}]
    # Who declared it is the caller, or nobody: never a field of the body.
    assert second.declared_by is None and third.declared_by == owner
    # The earlier revisions are kept, each exactly as recorded.
    assert _revisions(finding)[:1] == kept and len(_revisions(finding)) == 3

    served = scope.finding_scope(finding)
    assert (served["finding"], served["deployment"], served["current"]) == (str(finding.uuid), str(dep.uuid), 3)
    one, two, three = served["revisions"]
    assert [r["current"] for r in (one, two, three)] == [False, False, True]
    assert one["added"] == [scopes.item(primary), scopes.item(refund)] and one["removed"] == []
    assert (two["added"], two["removed"]) == ([scopes.item(backup)], [])
    assert (three["added"], three["removed"]) == ([], [scopes.item(refund)])
    assert [r["declared_by"] for r in (one, two, three)] == ["owner-d", None, "owner-d"]
    assert one["reason"] == "what the scan reached"


def test_a_recorded_revision_is_never_edited_in_place_or_deleted():
    finding = _incident()
    primary, backup = scopes.asset(finding.deployment), scopes.asset(finding.deployment, "backup-route")
    row = declare_scope(finding, primary)
    before = _revisions(finding)
    wider = [*row.items, {"kind": "asset", "ref": str(backup.uuid), "asset_kind": "gateway"}]

    row.items = wider
    for edit in (row.save, lambda: row.save(update_fields=["items"]), lambda: row.save(force_update=True), row.delete):
        with pytest.raises(IncidentScopeRewriteRefused):
            edit()
    recorded = IncidentScopeRevision.objects.filter(pk=row.pk)
    for rewrite in (
        lambda: recorded.update(items=wider),
        lambda: IncidentScopeRevision.objects.bulk_update([row], ["items"]),
        recorded.delete,
        lambda: IncidentScopeRevision.objects.bulk_create(
            [row], update_conflicts=True, unique_fields=["id"], update_fields=["items"]
        ),
    ):
        with pytest.raises(IncidentScopeRewriteRefused):
            rewrite()
    # A fresh instance carrying the recorded key, every part of it its own deployment's,
    # is an INSERT, which fails on the key.
    other = _incident("elsewhere")
    theirs = scopes.body(other, scopes.asset(other.deployment, "their-route"))
    imposter = IncidentScopeRevision(
        pk=row.pk, finding=other, revision=1, reason="x", items=scope.resolve_items(other, theirs["items"]),
        evidence=scope.resolve_evidence(other, theirs["evidence"]),
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        imposter.save()
    assert _revisions(finding) == before and _revisions(other) == []


def test_a_revision_supersedes_the_current_one_and_no_other():
    finding = _incident()
    primary, backup = scopes.asset(finding.deployment), scopes.asset(finding.deployment, "backup-route")
    first = declare_scope(finding, primary)
    wider = scopes.body(finding, primary, backup)
    items, evidence = scope.resolve_items(finding, wider["items"]), scope.resolve_evidence(finding, wider["evidence"])

    for number, supersedes, code in ((3, 2, "not_current"), (1, None, "not_current"), (2, None, "bad_supersedes")):
        row = IncidentScopeRevision(
            finding=finding, revision=number, supersedes=supersedes, items=items, reason="x", evidence=evidence
        )
        with pytest.raises(scope.ScopeRefused) as refused:
            row.save()
        assert refused.value.code == code, (number, supersedes)
    # S1's own codes for the rule (mythos_core.evidence_record): nothing local.
    assert {"not_current", "bad_supersedes", "evidence_required"} <= set(evidence_record.REFUSALS)
    assert _revisions(finding) == [IncidentScopeRevision._base_manager.filter(pk=first.pk).values().get()]


# ----------------------------------------------- items stay in one deployment


def _someone_elses(kind):
    """An item or a piece of evidence of another deployment, and one that does not exist."""
    other = _incident("elsewhere")
    if kind == "asset":
        return {"kind": "asset", "ref": str(scopes.asset(other.deployment, "their-route").uuid)}, {
            "kind": "asset", "ref": str(uuid.uuid4()),
        }
    if kind == "workflow":
        ApprovedWorkflow.objects.create(deployment=other.deployment, slug="their-payout", name="Payout")
        return {"kind": "workflow", "ref": "their-payout"}, {"kind": "workflow", "ref": "no-such-workflow"}
    return str(scopes.evidence_of(other).uuid), str(uuid.uuid4())


@pytest.mark.parametrize("kind", ["asset", "workflow", "evidence"])
def test_another_deployments_item_or_evidence_is_refused_exactly_as_one_that_does_not_exist(kind):
    finding = _incident()
    own = scopes.body(finding, scopes.asset(finding.deployment))
    theirs, nobodys = _someone_elses(kind)

    said = []
    for one in (theirs, nobodys):
        body = {**own, "evidence": [one]} if kind == "evidence" else {**own, "items": [*own["items"], one]}
        with pytest.raises(scope.ScopeRefused) as refused:
            scope.declare(finding, body=body)
        assert refused.value.code == "unknown_link", refused.value
        assert "this deployment" in str(refused.value)
        said.append(str(refused.value).replace(one if kind == "evidence" else one["ref"], "<ref>"))
    assert said[0] == said[1], "another deployment's reads as one that does not exist"
    assert _revisions(finding) == []


def test_the_record_itself_refuses_another_deployments_item_whoever_writes_it():
    """Not only the declaring function: a row built by hand is held to the same rule at save."""
    finding, other = _incident(), _incident("elsewhere")
    theirs = scopes.asset(other.deployment, "their-route")
    own_evidence = scope.resolve_evidence(finding, [str(scopes.evidence_of(finding).uuid)])
    forged = [{"kind": "asset", "ref": str(theirs.uuid), "asset_kind": "gateway"}]
    for write in (
        lambda: IncidentScopeRevision(finding=finding, revision=1, items=forged, reason="x", evidence=own_evidence).save(),
        lambda: IncidentScopeRevision.objects.create(
            finding=finding, revision=1, items=forged, reason="x", evidence=own_evidence
        ),
    ):
        with pytest.raises(scope.ScopeRefused) as refused:
            write()
        assert refused.value.code == "unknown_link"
    their_evidence = [{"uuid": str(scopes.evidence_of(other).uuid), "classification": "technically_verified"}]
    own_items = scope.resolve_items(finding, [scopes.item(scopes.asset(finding.deployment))])
    with pytest.raises(scope.ScopeRefused) as refused:
        IncidentScopeRevision(finding=finding, revision=1, items=own_items, reason="x", evidence=their_evidence).save()
    assert refused.value.code == "unknown_link"
    # A kind typed in beside an own asset is not what the asset is: refused too.
    mistyped = [{**own_items[0], "asset_kind": "model"}]
    with pytest.raises(scope.ScopeRefused):
        IncidentScopeRevision(finding=finding, revision=1, items=mistyped, reason="x", evidence=own_evidence).save()
    # A scope that holds nothing is refused at save as it is when declared.
    with pytest.raises(scope.ScopeRefused) as refused:
        IncidentScopeRevision(finding=finding, revision=1, items=[], reason="x", evidence=own_evidence).save()
    assert refused.value.code == "items_required"
    assert _revisions(finding) == []


def test_a_revision_names_its_items_its_reason_and_its_evidence_and_changes_something():
    finding = _incident()
    primary = scopes.asset(finding.deployment)
    good = scopes.body(finding, primary)
    for body, code in (
        ({**good, "items": []}, "items_required"),
        ({**good, "evidence": []}, "evidence_required"),
        ({**good, "reason": "  "}, "reason_required"),
        ({**good, "reason": "x" * 501}, "malformed"),
        ({**good, "reason": "first line\nSECOND-LINE"}, "malformed"),
        ({**good, "reason": "a tab\tSECOND-LINE"}, "malformed"),
        ({**good, "reason": "reordered \u202eSECOND-LINE"}, "malformed"),
        ({**good, "reason": "SECOND-LINE\x00"}, "malformed"),
        ({**good, "reason": ["SECOND-LINE"]}, "malformed"),
        ({**good, "reason": 7}, "malformed"),
        # A part left out is refused as that part posted empty: the client is told which.
        ({key: good[key] for key in ("items", "evidence")}, "reason_required"),
        ({key: good[key] for key in ("reason", "evidence")}, "items_required"),
        ({key: good[key] for key in ("items", "reason")}, "evidence_required"),
        ({}, "items_required"),
        ({**good, "items": [{"kind": "route", "ref": str(primary.uuid)}]}, "malformed"),
        ({**good, "items": [{**scopes.item(primary), "asset_kind": "model"}]}, "malformed"),
        ({**good, "items": [scopes.item(primary), scopes.item(primary)]}, "malformed"),
        ({**good, "items": "everything"}, "malformed"),
        ({**good, "revision": 7}, "not_posted"),
        ({**good, "declared_by": "owner-d"}, "not_posted"),
        ({**good, "supersedes": None}, "not_posted"),
        ("everything", "malformed"),
    ):
        with pytest.raises(scope.ScopeRefused) as refused:
            scope.declare(finding, body=body)
        assert refused.value.code == code, body
        assert "SECOND-LINE" not in str(refused.value), "a refusal never repeats the text it refused"
    assert _revisions(finding) == []
    # Exactly 500 printable characters on one line is a reason.
    assert scope._reason("x" * 500) == "x" * 500

    scope.declare(finding, body=good)
    with pytest.raises(scope.ScopeRefused) as refused:
        scope.declare(finding, body=scopes.body(finding, primary, reason="the same items again"))
    assert refused.value.code == "nothing_changed"
    assert len(_revisions(finding)) == 1


# --------------------------------------- what holds a recovered state back, as data


def _rev(number, *items):
    return SimpleNamespace(revision=number, items=[{"kind": "asset", "ref": ref} for ref in items])


@pytest.mark.parametrize(
    ("taken_under", "revisions", "expected"),
    [
        (None, [], [NOT_DECLARED]),
        (None, [_rev(1, "a")], [NOT_DECLARED]),
        (1, [_rev(1, "a")], []),
        (1, [_rev(1, "a"), _rev(2, "a", "b")], ["scope:revision:2:added:asset:b"]),
        (2, [_rev(1, "a"), _rev(2, "a", "b")], []),
        # Only removes: nothing is held back. A narrowing takes no recovered state away.
        (1, [_rev(1, "a", "b"), _rev(2, "a")], []),
        # Added, then removed again: the removal ends the hold.
        (1, [_rev(1, "a"), _rev(2, "a", "b"), _rev(3, "a")], []),
        # Two added, one removed: still held by the other.
        (1, [_rev(1, "a"), _rev(2, "a", "b", "c"), _rev(3, "a", "b")], ["scope:revision:2:added:asset:b"]),
        # Removed, then added back: the later revision added it.
        (1, [_rev(1, "a", "b"), _rev(2, "a"), _rev(3, "a", "b")], ["scope:revision:3:added:asset:b"]),
        (1, [_rev(1, "a"), _rev(2, "a", "b"), _rev(3, "a", "b", "c")], [
            "scope:revision:2:added:asset:b", "scope:revision:3:added:asset:c",
        ]),
        # A revision that is not on record is no declared scope.
        (3, [_rev(1, "a"), _rev(2, "a", "b")], [NOT_DECLARED]),
        # Unreadable is caution, whichever revision it is.
        (1, [_rev(1, "a"), SimpleNamespace(revision=2, items=[{"kind": "asset"}])], ["scope:unreadable"]),
        (2, [SimpleNamespace(revision=1, items="a"), _rev(2, "a")], ["scope:unreadable"]),
    ],
)
def test_what_holds_a_recovered_state_back_is_each_item_a_later_revision_added_that_is_in_scope_now(taken_under, revisions, expected):
    assert scope.holds(taken_under, revisions) == expected


def test_an_item_counts_from_when_it_was_last_added_and_a_removed_one_is_listed_not_held():
    who = SimpleNamespace(username="alice")
    narrowed = SimpleNamespace(revision=3, items=_rev(3, "a").items, declared_by=who, declared_by_id=7, reason="a false alarm")
    revisions = [_rev(1, "a"), _rev(2, "a", "b"), narrowed, _rev(4, "a", "b", "c")]
    assert scope.since(revisions, 2) == {("asset", "a"): 1, ("asset", "b"): 2}
    assert scope.since(revisions, 3) == {("asset", "a"): 1}
    # Removed and added again, it counts from when it was added again.
    assert scope.since(revisions) == {("asset", "a"): 1, ("asset", "b"): 4, ("asset", "c"): 4}
    gone = {"kind": "asset", "ref": "b", "added": 2, "removed": 3, "removed_by": "alice", "reason": "a false alarm"}
    assert scope.removed(revisions, 2) == [] and scope.removed(revisions, 3) == [gone] == scope.removed(revisions)
    # An item of the first scope was never added to an earlier one: its removal is not listed here.
    assert scope.removed([_rev(1, "a", "b"), _rev(2, "a")]) == []
    unreadable = [_rev(1, "a"), SimpleNamespace(revision=2, items="b")]
    assert scope.since(unreadable) is None and scope.removed(unreadable) is None


# What names an added item, by the kind of item and the kind of link. Revision 2 added
# the asset ``b`` and the workflow ``w`` at ADDED; everything is judged for a step under it.
ADDED = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
EARLIER, LATER = (ADDED - timedelta(hours=1)).isoformat(), (ADDED + timedelta(hours=1)).isoformat()
_TWO = [
    SimpleNamespace(revision=1, items=[{"kind": "asset", "ref": "a"}], declared_at=ADDED - timedelta(days=9)),
    SimpleNamespace(
        revision=2, declared_at=ADDED,
        items=[{"kind": "asset", "ref": "a"}, {"kind": "asset", "ref": "b"}, {"kind": "workflow", "ref": "w"}],
    ),
]
_BOTH = ("asset:b", "workflow:w")


def _looked(required=_BOTH, observed=_BOTH, basis="observed") -> dict:
    return {
        "sources": [{"source": one, "kind": "scope", "start": T0, "end": T1} for one in required],
        "observations": [{"source": one, "start": T0, "end": T1, "basis": basis} for one in observed],
    }


_EVIDENCE = {"uuid": "e-1", "classification": "technically_verified", "asset": "b"}
_PERMIT = {"outcome_id": "p-1", "workflow": "w"}
#: link kind -> (links, coverage manifest)
_LINKS = {
    "evidence": ({"evidence": [_EVIDENCE]}, {}),
    "permit": ({"permits": [_PERMIT]}, {}),
    "coverage observed": ({"coverage_recorded_at": LATER}, _looked()),
    "coverage not observed": ({"coverage_recorded_at": LATER}, _looked(observed=())),
    "coverage inferred, not observed": ({"coverage_recorded_at": LATER}, _looked(basis="inferred")),
    "coverage of a source not required": ({"coverage_recorded_at": LATER}, _looked(required=())),
    "coverage older than the revision": ({"coverage_recorded_at": EARLIER}, _looked()),
    # As resolve() records a link that is not this deployment's: evidence whose asset is
    # not its own names none; a permit of another workflow; a look at another asset.
    "other deployment": (
        {"evidence": [{**_EVIDENCE, "asset": None}], "permits": [{**_PERMIT, "workflow": "theirs"}],
         "coverage_recorded_at": LATER},
        _looked(required=("asset:z",), observed=("asset:z",)),
    ),
    "unreadable": (
        {"evidence": ["e-1", {"uuid": "e-2"}], "permits": [{"outcome_id": "p-1"}, None], "coverage_recorded_at": "lately"},
        _looked(),
    ),
    "unreadable, no time at all": ({}, _looked()),
}
#: (item kind, link kind) -> the kinds of link that name the item. Every cell is stated.
_NAMES = {
    ("asset", "evidence"): ["evidence"], ("workflow", "evidence"): [],
    ("asset", "permit"): [], ("workflow", "permit"): ["permit"],
    ("asset", "coverage observed"): ["coverage"], ("workflow", "coverage observed"): [],
    ("asset", "coverage not observed"): [], ("workflow", "coverage not observed"): [],
    ("asset", "coverage inferred, not observed"): [], ("workflow", "coverage inferred, not observed"): [],
    ("asset", "coverage of a source not required"): [], ("workflow", "coverage of a source not required"): [],
    ("asset", "coverage older than the revision"): [], ("workflow", "coverage older than the revision"): [],
    ("asset", "other deployment"): [], ("workflow", "other deployment"): [],
    ("asset", "unreadable"): [], ("workflow", "unreadable"): [],
    ("asset", "unreadable, no time at all"): [], ("workflow", "unreadable, no time at all"): [],
}


@pytest.mark.parametrize(("item", "link"), sorted(_NAMES))
def test_an_added_item_is_named_only_by_the_right_kind_of_link_of_its_own_deployment(item, link):
    assert {link for _item, link in _NAMES} == set(_LINKS), "every link kind is judged for every kind of item"
    links, coverage = _LINKS[link]
    manifest = rr.manifest_of(SimpleNamespace(uuid="f-1"), coverage)
    ref = {"asset": "b", "workflow": "w"}[item]

    items = rr.scope_items(links, manifest, 2, _TWO)

    (named,) = [one for one in items["added"] if (one["kind"], one["ref"]) == (item, ref)]
    assert [by["kind"] for by in named["covered_by"]] == _NAMES[(item, link)]
    assert named["revision"] == 2 and items["removed"] == []
    # What nothing names is an open gap, by name; what something names is none.
    open_gap = f"scope:revision:2:added:{item}:{ref}"
    assert (open_gap in rr.scope_holds_of(2, _TWO, links, manifest)) is (not _NAMES[(item, link)])
    # The first scope's own item is not tied one by one.
    assert ("asset", "a") not in {(one["kind"], one["ref"]) for one in items["added"]}


_UNKNOWN = {"added": None, "removed": None}


@pytest.mark.parametrize(
    ("taken_under", "revisions"),
    [
        (None, []),
        (None, [_rev(1, "a")]),
        # It names a revision that is not among them.
        (3, [_rev(1, "a"), _rev(2, "a", "b")]),
        (1, []),
        # A revision at or before its own cannot be read.
        (2, [_rev(1, "a"), SimpleNamespace(revision=2, items="b")]),
        (2, [SimpleNamespace(revision=1, items=[{"kind": "asset"}]), _rev(2, "a")]),
    ],
)
def test_what_a_scope_gained_and_lost_reads_unknown_where_it_cannot_be_established(taken_under, revisions):
    """No declared scope, or one that cannot be read: not known. Never an empty list,
    which would say that nothing was added and nothing was removed."""
    manifest = rr.manifest_of(SimpleNamespace(uuid="f-1"), _looked())
    assert rr.scope_items({}, manifest, taken_under, revisions) == _UNKNOWN
    # Unknown never reads as nothing to name: the scope's own hold stands beside it.
    assert set(rr.scope_holds_of(taken_under, revisions, {}, manifest)) & {NOT_DECLARED, "scope:unreadable"}


def test_a_readable_scope_says_what_it_gained_and_lost_even_when_it_holds_nothing_now():
    manifest = rr.manifest_of(SimpleNamespace(uuid="f-1"), _looked())
    # Readable as of its own revision, whatever a later one holds: known.
    later = [_rev(1, "a"), SimpleNamespace(revision=2, items="b")]
    assert rr.scope_items({}, manifest, 1, later) == {"added": [], "removed": []}
    assert rr.scope_holds_of(1, later, {}, manifest) == ["scope:unreadable"]
    # A scope that holds nothing now gained nothing, and still lists what it lost.
    # (Declaring one is refused, so only a row written past the guard is one.)
    who = SimpleNamespace(username="alice")
    emptied = SimpleNamespace(revision=3, items=[], declared_by=who, declared_by_id=7, reason="the last one was a false alarm")
    gone = {
        "kind": "asset", "ref": "b", "added": 2, "removed": 3, "removed_by": "alice",
        "reason": "the last one was a false alarm",
    }
    first_emptied = [_rev(1, "a"), _rev(2, "a", "b"), emptied]
    assert rr.scope_items({}, manifest, 3, first_emptied) == {"added": [], "removed": [gone]}


# ------------------------------------------- no declared scope is unknown, never ok


@pytest.mark.parametrize("recovered", [st.RECOVERY_ACCEPTED, st.RESTORED_WITH_RESTRICTIONS])
def test_with_no_declared_scope_no_step_reaches_a_recovered_state_and_it_says_so(recovered):
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    _repaired_and_tested(finding)
    if recovered == st.RECOVERY_ACCEPTED:
        asked = {"by": owner, "body": {"coverage": COVERED}, "accept_until": _until()}
    else:
        permit = _permit(dep)
        receipt = record_reconciliation(dep, WF, permit, "applied").receipt_id
        asked = {"body": {"permits": [permit], "receipts": [receipt], "restrictions": ["manual-only"], "coverage": COVERED}}

    steps = rr.record(finding, **asked)

    # Every witness and complete coverage, and still not recovered: the scope is unknown.
    assert _states(steps) == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    held = steps[-1]
    assert held.scope_revision is None
    assert held.gaps == [NOT_DECLARED] and held.release == st.AUDIT_INCOMPLETE
    assert {"statement": NOT_DECLARED, "sources": [{"kind": "scope", "ref": f"finding:{finding.uuid}"}]} in (
        held.residual_uncertainty
    )
    assert not RecoveryRecord.objects.filter(finding=finding, state__in=sorted(rr.RECOVERED)).exists()
    assert st.PASS not in [step.release for step in steps]
    read = _read(finding)
    assert read["scope_revision"] is None
    assert all(step["scope_revision"] is None and step["scope_gaps"] == [NOT_DECLARED] for step in read["steps"])
    assert read["current"] == {"version": 3, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}

    # Declared, the next step is the recovered one, under the revision it names.
    declare_scope(finding)
    assert _read(finding)["current"]["state"] == st.REPAIR_TESTED, "a declaration records no step"
    (reached,) = rr.record(finding, **{key: value for key, value in asked.items() if key != "body"})
    assert (reached.state, reached.scope_revision, NOT_DECLARED in reached.gaps) == (recovered, 1, False)
    assert reached.release == (st.PASS if recovered == st.RECOVERY_ACCEPTED else st.FAIL)


def test_a_step_names_the_current_scope_revision_and_any_other_is_refused_at_save():
    finding = _incident()
    primary, backup = scopes.asset(finding.deployment), scopes.asset(finding.deployment, "backup-route")
    (first,) = rr.record(finding)
    assert first.scope_revision is None
    declare_scope(finding, primary)
    declare_scope(finding, primary, backup)
    _repaired_and_tested(finding)
    links, coverage = rr.resolve(finding, None, first)
    revisions = scope.revisions_of([finding.pk])[finding.pk]

    # Derived under revision 1, or under none, once revision 2 is current.
    for stale in (revisions[:1], []):
        row = rr.draft(finding, version=2, links=links, coverage=coverage, previous=first, revisions=stale)
        assert row.scope_revision == (1 if stale else None)
        with pytest.raises(rr.RecoveryRefused) as refused:
            row.save()
        assert refused.value.code == "not_derived"
    # Derived under the current one and then typed over.
    row = rr.draft(finding, version=2, links=links, coverage=coverage, previous=first, revisions=revisions)
    row.scope_revision = 1
    with pytest.raises(rr.RecoveryRefused):
        row.save()
    assert len(_history(finding)) == 1
    row = rr.draft(finding, version=2, links=links, coverage=coverage, previous=first, revisions=revisions)
    row.save()
    assert (row.state, row.scope_revision) == (st.REPAIR_PROPOSED, 2)


# ------------------------------------- no recovery outlives the scope it was taken under


def test_an_accepted_recovery_does_not_outlive_a_wider_scope():
    """The fail-first: on master this recovery stays ``recovery_accepted`` and ``PASS``."""
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary = scopes.asset(dep, "primary-route")
    steps = _accepted(finding, primary)
    before = _history(finding)
    assert _read(finding)["current"] == {"version": 4, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}

    # A backup route nobody knew of is found: the scope widens.
    backup = scopes.asset(dep, "backup-route")
    declare_scope(finding, primary, backup, reason="a backup route found in the firewall export")

    read = _read(finding)
    assert read["scope_revision"] == 2
    assert read["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
    last = read["steps"][-1]
    assert (last["state"], last["release"], last["scope_revision"]) == (st.REPAIR_TESTED, st.AUDIT_INCOMPLETE, 1)
    # It names the revision and the added item among the gaps.
    assert last["gaps"] == [_added(2, backup)] and last["scope_gaps"] == [_added(2, backup)]
    # Nothing the read shows as standing is recovered or a pass. What was recorded is kept.
    assert not any(state in rr.RECOVERED or release == st.PASS for state, release in _standing(read))
    assert last["recorded"] == {"state": st.RECOVERY_ACCEPTED, "gaps": [], "release": st.PASS}
    # The revision recorded no step and rewrote none: the row is history.
    assert _history(finding) == before

    # An empty step answers nothing and moves nothing: not an admin's, not the owner's
    # with a new acceptance, and not one whose evidence names none of the added items.
    someone = User.objects.create_user(username="another-admin", password="x", role=User.Roles.ADMIN)
    beside = [str(scopes.evidence_naming(primary).uuid), str(scopes.evidence_of(finding).uuid)]
    for asked in ({"by": someone}, {"by": owner, "accept_until": _until()}, {"by": someone, "body": {"evidence": beside}}):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, **asked)
        assert refused.value.code == "nothing_moved" and _added(2, backup) in str(refused.value), asked
    assert _history(finding) == before

    # Evidence that names the backup route: now the steps are recorded, under the new
    # revision. The first names the accepted step it sets aside.
    proof = scopes.evidence_naming(backup)
    again = rr.record(finding, by=someone, body={"evidence": [str(proof.uuid)]})
    assert _states(again) == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    assert [(s.version, s.scope_revision) for s in again] == [(5, 2), (6, 2), (7, 2)]
    assert [s.reopens for s in again] == [str(steps[-1].uuid), "", ""]
    assert again[0].links["evidence"] == [
        {"uuid": str(proof.uuid), "classification": "technically_verified", "asset": str(backup.uuid)}
    ]
    # S1 lets nothing follow an accepted recovery, not even a reopen: asked about this
    # step, it refuses. The rule belongs in mythos_core.status and is not there yet.
    with pytest.raises(st.RecoveryError) as terminal:
        st.check_recovery_step(rr._as_recovery(steps[-1]), rr._as_recovery(again[0]))
    assert terminal.value.code == "terminal"
    assert _read(finding)["current"] == {"version": 7, "state": st.REPAIR_TESTED, "release": st.FAIL}
    # The evidence is carried, as every link is: the owner's acceptance needs no more.
    (accepted,) = rr.record(finding, by=owner, accept_until=_until())
    assert (accepted.state, accepted.release, accepted.scope_revision) == (st.RECOVERY_ACCEPTED, st.PASS, 2)
    for earlier, later in zip([*again, accepted], [*again[1:], accepted], strict=False):
        st.check_recovery_step(rr._as_recovery(earlier), rr._as_recovery(later))

    read = _read(finding)
    assert read["current"] == {"version": 8, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}
    # The acceptance under revision 1 stays what it was, and still does not stand.
    assert (read["steps"][3]["release"], read["steps"][3]["recorded"]["release"]) == (st.AUDIT_INCOMPLETE, st.PASS)
    assert _history(finding)[:4] == before
    # Accepted under the current revision, it is final again.
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner)
    assert refused.value.code == "terminal"


def test_an_empty_step_never_re_derives_a_recovered_state_under_a_wider_scope():
    """The fail-first for the open gap: on ``4e0992d`` the empty step below recorded
    ``restored_with_restrictions`` again, under revision 2, on the witnesses it had."""
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    restored = _restored(finding, primary)[-1]
    before = _history(finding)
    backup = scopes.asset(dep, "backup-route")
    declare_scope(finding, primary, backup)

    read = _read(finding)
    assert read["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
    assert read["steps"][-1]["gaps"] == [_added(2, backup)]
    assert read["steps"][-1]["recorded"]["state"] == st.RESTORED_WITH_RESTRICTIONS

    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding)
    assert refused.value.code == "nothing_moved" and _added(2, backup) in str(refused.value)
    assert _history(finding) == before
    assert _read(finding)["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}

    # Evidence that names the added item. S1's reopen: new evidence reopened the scope,
    # and the new record names the one it reopens.
    proof = scopes.evidence_naming(backup)
    again = rr.record(finding, body={"evidence": [str(proof.uuid)]})
    assert _states(again) == [
        st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED, st.RESTORED_WITH_RESTRICTIONS,
    ]
    assert again[0].reopens == str(restored.uuid) and {s.scope_revision for s in again} == {2}
    for earlier, later in zip([restored, *again], again, strict=False):
        st.check_recovery_step(rr._as_recovery(earlier), rr._as_recovery(later))
    read = _read(finding)
    assert read["current"] == {"version": 8, "state": st.RESTORED_WITH_RESTRICTIONS, "release": st.FAIL}
    assert read["steps"][-1]["scope_gaps"] == [] and _history(finding)[:4] == before

    # The evidence taken away again, the restore loses its support: the next steps name
    # the item among their gaps, and none is a recovered state.
    without = rr.record(finding, body={"evidence": []})
    assert _states(without) == [st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    assert without[-1].gaps == [_added(2, backup)] and without[-1].release == st.AUDIT_INCOMPLETE


def test_evidence_for_one_added_item_covers_that_item_and_no_other():
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    _restored(finding, primary)
    backup, modem = scopes.asset(dep, "backup-route"), scopes.asset(dep, "vendor-modem")
    declare_scope(finding, primary, backup, modem)

    one = scopes.evidence_naming(backup)
    again = rr.record(finding, body={"evidence": [str(one.uuid)]})

    # It answered for one item, so the steps are recorded; the other holds the restore back.
    assert _states(again) == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    held = again[-1]
    assert held.gaps == [_added(2, modem)] and held.release == st.AUDIT_INCOMPLETE
    assert not RecoveryRecord.objects.filter(finding=finding, scope_revision=2, state__in=sorted(rr.RECOVERED)).exists()
    read = _read(finding)
    assert read["current"] == {"version": 7, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
    assert read["steps"][-1]["scope_gaps"] == [_added(2, modem)]
    # More evidence for the same item is not evidence for the other.
    more = scopes.evidence_naming(backup)
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, body={"evidence": [str(one.uuid), str(more.uuid)]})
    assert refused.value.code == "nothing_moved"

    other = scopes.evidence_naming(modem)
    (restored,) = rr.record(finding, body={"evidence": [str(one.uuid), str(other.uuid)]})
    assert (restored.state, restored.scope_revision, restored.gaps) == (st.RESTORED_WITH_RESTRICTIONS, 2, [])


def test_an_item_added_before_any_recovery_is_an_open_gap_until_evidence_names_it():
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary = scopes.asset(dep, "primary-route")
    declare_scope(finding, primary)
    rr.record(finding)
    backup = scopes.asset(dep, "backup-route")
    declare_scope(finding, primary, backup)
    _repaired_and_tested(finding)

    # Every witness, complete coverage and the owner's acceptance: held back by the item.
    steps = rr.record(finding, by=owner, body={"coverage": COVERED}, accept_until=_until())
    assert _states(steps) == [st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    held = steps[-1]
    assert (held.gaps, held.release, held.scope_revision) == ([_added(2, backup)], st.AUDIT_INCOMPLETE, 2)
    assert {"statement": _added(2, backup), "sources": [{"kind": "scope", "ref": f"finding:{finding.uuid}"}]} in (
        held.residual_uncertainty
    )
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner, accept_until=_until())
    assert refused.value.code == "nothing_moved"

    proof = scopes.evidence_naming(backup)
    (accepted,) = rr.record(finding, by=owner, body={"evidence": [str(proof.uuid)]}, accept_until=_until())
    assert (accepted.state, accepted.release, accepted.gaps) == (st.RECOVERY_ACCEPTED, st.PASS, [])


def test_another_deployments_evidence_never_covers_an_added_item():
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    restored = _restored(finding, primary)[-1]
    backup = scopes.asset(dep, "backup-route")
    declare_scope(finding, primary, backup)
    before = _history(finding)
    other = _incident("elsewhere")

    # Evidence of ANOTHER deployment's finding, attached by a bad write to this
    # deployment's backup route: not evidence of this deployment, refused as every link is.
    theirs = Finding.objects.create(
        deployment=other.deployment, asset=backup, fingerprint="fp-theirs", finding_type="exposed_route",
        title="theirs", severity="high",
    )
    foreign = Evidence.objects.create(finding=theirs, classification="technically_verified")
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, body={"evidence": [str(foreign.uuid)]})
    assert refused.value.code == "unknown_link" and "this deployment" in str(refused.value)

    # Evidence of this deployment's finding attached to another deployment's asset of
    # the same name names nothing of this scope.
    their_route = scopes.asset(other.deployment, "backup-route")
    stray_finding = Finding.objects.create(
        deployment=dep, asset=their_route, fingerprint="fp-stray", finding_type="exposed_route", title="stray",
        severity="high",
    )
    stray = Evidence.objects.create(finding=stray_finding, classification="technically_verified")
    links, _coverage = rr.resolve(finding, {"evidence": [str(stray.uuid)]}, restored)
    assert links["evidence"] == [{"uuid": str(stray.uuid), "classification": "technically_verified", "asset": None}]
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, body={"evidence": [str(stray.uuid)]})
    assert refused.value.code == "nothing_moved"
    assert _history(finding) == before


def _gate(dep, workflow=WF):
    return record_signed(dep, workflow, oc.HELD, datetime.now(UTC) - timedelta(minutes=2)).outcome_id


def test_a_permit_of_that_workflow_names_it():
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    restored = _restored(finding, primary)[-1]
    (permit,) = [one["outcome_id"] for one in restored.links["permits"]]
    refund = ApprovedWorkflow.objects.create(deployment=dep, slug=WF, name="Refund")
    declare_scope(finding, primary, refund)
    open_gap = f"scope:revision:2:added:workflow:{WF}"
    assert _read(finding)["steps"][-1]["gaps"] == [open_gap]

    # The step links a signed gate decision of that workflow, resolved now as every
    # permit is: it names the workflow, and the step under the new revision says so.
    again = rr.record(finding)
    assert _states(again)[-1] == st.RESTORED_WITH_RESTRICTIONS and again[-1].scope_revision == 2
    assert again[-1].scope_items == {
        "added": [{"revision": 2, "kind": "workflow", "ref": WF, "covered_by": [{"kind": "permit", "ref": permit}]}],
        "removed": [],
    }
    assert _read(finding)["steps"][-1]["scope_items"] == again[-1].scope_items


def test_no_other_permit_names_a_workflow_a_revision_adds():
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    restored = _restored(finding, primary)[-1]
    (refund_permit,) = [one["outcome_id"] for one in restored.links["permits"]]
    payout = ApprovedWorkflow.objects.create(deployment=dep, slug="payout", name="Payout")
    declare_scope(finding, primary, payout)
    before = _history(finding)
    open_gap = "scope:revision:2:added:workflow:payout"

    # A permit of another workflow, evidence, and a look at it in the coverage manifest: none names it.
    looked = {
        "sources": [*COVERED["sources"], {"source": "workflow:payout", "kind": "workflow", "start": T0, "end": T1}],
        "observations": [*COVERED["observations"], {"source": "workflow:payout", "start": T0, "end": T1, "basis": "observed"}],
    }
    for body in ({}, {"evidence": [str(scopes.evidence_naming(primary).uuid)]}, {"coverage": looked}):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, body=body)
        assert refused.value.code == "nothing_moved" and open_gap in str(refused.value), body
    # Another deployment's permit of a workflow of that very name is not a link of this one.
    other = _incident("elsewhere")
    theirs = _gate(other.deployment, "payout")
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, body={"permits": [refund_permit, theirs]})
    assert refused.value.code == "unknown_link" and "this deployment" in str(refused.value)
    assert _history(finding) == before

    own = _gate(dep, "payout")
    again = rr.record(finding, body={"permits": [refund_permit, own]})
    assert _states(again)[-1] == st.RESTORED_WITH_RESTRICTIONS
    assert again[-1].scope_items["added"] == [
        {"revision": 2, "kind": "workflow", "ref": "payout", "covered_by": [{"kind": "permit", "ref": own}]}
    ]


def _looked_at(*assets, observed=True) -> dict:
    """The covered manifest, with each of ``assets`` a required source, observed or not."""
    named = [f"asset:{asset.uuid}" for asset in assets]
    return {
        "sources": [*COVERED["sources"], *({"source": one, "kind": "asset", "start": T0, "end": T1} for one in named)],
        "observations": [
            *COVERED["observations"],
            *({"source": one, "start": T0, "end": T1, "basis": "observed"} for one in named if observed),
        ],
    }


def test_an_added_asset_on_which_nothing_was_found_is_named_by_a_look_recorded_after_it_was_added():
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary, backup = scopes.asset(dep, "primary-route"), scopes.asset(dep, "backup-route")
    # Under revision 1 the manifest already observes the backup route: a look from
    # before the route was in scope.
    declare_scope(finding, primary)
    _repaired_and_tested(finding)
    permit = _gate(dep)
    receipt = record_reconciliation(dep, WF, permit, "applied").receipt_id
    body = {"permits": [permit], "receipts": [receipt], "restrictions": ["refunds-manual-only"]}
    restored = rr.record(finding, body={**body, "coverage": _looked_at(backup)})[-1]
    assert (restored.state, restored.scope_revision, restored.scope_items) == (
        st.RESTORED_WITH_RESTRICTIONS, 1, {"added": [], "removed": []},
    )
    declare_scope(finding, primary, backup, by=owner)
    before = _history(finding)
    open_gap = _added(2, backup)

    # The look from before says nothing of the route now; nor does a manifest that lists
    # it and does not observe it.
    for asked in ({}, {"coverage": _looked_at(backup, observed=False)}):
        with pytest.raises(rr.RecoveryRefused) as refused:
            rr.record(finding, body=asked)
        assert refused.value.code == "nothing_moved" and open_gap in str(refused.value), asked
    assert _history(finding) == before

    # Looked at again, after it was added: named, as a look that found nothing.
    again = rr.record(finding, body={"coverage": _looked_at(backup)})
    assert _states(again)[-1] == st.RESTORED_WITH_RESTRICTIONS and again[-1].gaps == []
    look = {"kind": "coverage", "ref": f"asset:{backup.uuid}"}
    assert again[-1].scope_items == {
        "added": [{"revision": 2, "kind": "asset", "ref": str(backup.uuid), "covered_by": [look]}], "removed": [],
    }
    # Found and linked reads as that, beside the look: never one for the other.
    proof = scopes.evidence_naming(backup)
    links, _coverage = rr.resolve(finding, {"evidence": [str(proof.uuid)]}, again[-1])
    both = rr.scope_items(links, rr.manifest_of(finding, again[-1].coverage), 2, scope.revisions_of([finding.pk])[finding.pk])
    assert both["added"][0]["covered_by"] == [{"kind": "evidence", "ref": str(proof.uuid)}, look]

    # Removed, openly: no longer a gap, and listed with who removed it and why.
    declare_scope(finding, primary, by=owner, reason="the backup route was decommissioned")
    gone = {
        "kind": "asset", "ref": str(backup.uuid), "added": 2, "removed": 3, "removed_by": owner.username,
        "reason": "the backup route was decommissioned",
    }
    read = _read(finding)
    assert read["current"]["state"] == st.RESTORED_WITH_RESTRICTIONS and read["steps"][-1]["scope_gaps"] == []
    assert read["scope_removed"] == [gone]
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding)
    assert refused.value.code == "nothing_moved"

    # Added again, it counts from when it was added again: the look from revision 2 is
    # older than that, and the item is open until it is looked at again.
    declare_scope(finding, primary, backup, by=owner, reason="the route is back in service")
    again_open = _added(4, backup)
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding)
    assert refused.value.code == "nothing_moved" and again_open in str(refused.value)
    last = rr.record(finding, body={"coverage": _looked_at(backup)})[-1]
    assert last.state == st.RESTORED_WITH_RESTRICTIONS
    assert last.scope_items == {
        "added": [{"revision": 4, "kind": "asset", "ref": str(backup.uuid), "covered_by": [look]}], "removed": [gone],
    }


def test_a_failed_read_back_is_recorded_whatever_the_scope():
    """A blocker is never held back by an open gap in the scope."""
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    restored = _restored(finding, primary)[-1]
    declare_scope(finding, primary, scopes.asset(dep, "backup-route"))
    permit = restored.links["permits"][0]["outcome_id"]
    failed = record_reconciliation(dep, WF, permit, "not_applied").receipt_id

    steps = rr.record(finding, body={"receipts": [failed]})

    assert _states(steps) == [st.UNDER_INVESTIGATION, st.RECOVERY_INCOMPLETE]
    assert steps[0].reopens == str(restored.uuid)
    assert steps[-1].gaps == [f"effect_not_applied:receipt:{failed}"] and steps[-1].release == st.FAIL


def _gone(record, added, removed, by, reason) -> dict:
    """``record`` as the derived record lists an item a revision added and a later one removed."""
    return {**scopes.item(record), "added": added, "removed": removed, "removed_by": by.username, "reason": reason}


def test_a_narrowing_ends_the_hold_for_the_item_it_removes_and_says_so():
    """Accepted, widened, narrowed, with no step between: the acceptance stands again."""
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary = scopes.asset(dep, "primary-route")
    _accepted(finding, primary)
    backup = scopes.asset(dep, "backup-route")
    declare_scope(finding, primary, backup)
    before = _history(finding)
    assert _read(finding)["steps"][-1]["gaps"] == [_added(2, backup)]

    # Without a reason, or without its author, the removal is refused.
    for asked, code in (({"by": owner, "reason": " "}, "reason_required"), ({"reason": "a false alarm"}, "declared_by_required")):
        with pytest.raises(scope.ScopeRefused) as refused:
            declare_scope(finding, primary, **asked)
        assert refused.value.code == code
    why = "a false alarm: the route was never connected"
    declare_scope(finding, primary, by=owner, reason=why)

    # The hold stood only while the item was in scope. The acceptance covered what is
    # in scope now: it stands again, with no new step, and the removal is disclosed.
    read = _read(finding)
    assert read["scope_revision"] == 3
    assert read["current"] == {"version": 4, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}
    assert (read["steps"][-1]["gaps"], read["steps"][-1]["scope_gaps"]) == ([], [])
    assert read["scope_removed"] == [_gone(backup, 2, 3, owner, why)]
    assert _history(finding) == before, "a revision records no step"
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner)
    assert refused.value.code == "terminal"

    # Only ever narrowed: a revision that only removes takes no recovered state away.
    other = _incident("narrowed")
    one, two = scopes.asset(other.deployment, "primary-route"), scopes.asset(other.deployment, "spare-route")
    _accepted(other, one, two)
    before = _history(other)
    declare_scope(other, one, by=other.deployment.owner, reason="the spare route was never reachable")
    read = _read(other)
    assert read["current"] == {"version": 4, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}
    assert read["steps"][-1]["scope_gaps"] == [] and _history(other) == before
    # Removed from the first scope, it was never added to an earlier one: not listed.
    assert read["scope_removed"] == []


def test_a_chain_reopened_for_an_item_goes_on_once_a_narrowing_removes_it():
    """Accepted, widened, reopened by a step, narrowed: the next step is accepted, and names the removal."""
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary = scopes.asset(dep, "primary-route")
    _accepted(finding, primary)
    backup, modem = scopes.asset(dep, "backup-route"), scopes.asset(dep, "vendor-modem")
    declare_scope(finding, primary, backup, modem)
    proof = scopes.evidence_naming(backup)
    reopened = rr.record(finding, by=owner, body={"evidence": [str(proof.uuid)]}, accept_until=_until())
    assert _states(reopened) == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED]
    assert reopened[-1].gaps == [_added(2, modem)] and reopened[-1].release == st.AUDIT_INCOMPLETE
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner, accept_until=_until())
    assert refused.value.code == "nothing_moved"

    why = "the modem was never on this network"
    declare_scope(finding, primary, backup, by=owner, reason=why)

    # The removal answered the hold: the step under the narrowed revision is derived by
    # SP-1's own rules from the links it carries, and lists what was removed.
    (accepted,) = rr.record(finding, by=owner, accept_until=_until())
    assert (accepted.state, accepted.release, accepted.scope_revision, accepted.gaps) == (
        st.RECOVERY_ACCEPTED, st.PASS, 3, [],
    )
    assert accepted.scope_items == {
        "added": [{
            "revision": 2, "kind": "asset", "ref": str(backup.uuid),
            "covered_by": [{"kind": "evidence", "ref": str(proof.uuid)}],
        }],
        "removed": [_gone(modem, 2, 3, owner, why)],
    }


def test_two_items_added_and_one_removed_is_still_held_by_the_other():
    """Accepted, widened by two items, one removed: the other still holds it."""
    finding = _incident()
    dep, owner = finding.deployment, finding.deployment.owner
    primary = scopes.asset(dep, "primary-route")
    _accepted(finding, primary)
    backup, modem = scopes.asset(dep, "backup-route"), scopes.asset(dep, "vendor-modem")
    declare_scope(finding, primary, backup, modem)
    before = _history(finding)
    why = "the modem was never on this network"
    declare_scope(finding, primary, backup, by=owner, reason=why)

    read = _read(finding)
    assert read["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
    assert read["steps"][-1]["gaps"] == [_added(2, backup)]
    assert read["scope_removed"] == [_gone(modem, 2, 3, owner, why)]
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner, accept_until=_until())
    assert refused.value.code == "nothing_moved" and _added(2, backup) in str(refused.value)
    assert _history(finding) == before


def test_a_step_held_for_want_of_a_scope_is_not_advanced_by_declaring_one():
    finding = _incident()
    owner = finding.deployment.owner
    _repaired_and_tested(finding)
    held = rr.record(finding, by=owner, body={"coverage": COVERED}, accept_until=_until())[-1]
    assert (held.state, held.release) == (st.REPAIR_TESTED, st.AUDIT_INCOMPLETE)
    before = _history(finding)

    declare_scope(finding)

    assert _history(finding) == before
    assert _read(finding)["current"] == {"version": 3, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}


# ------------------------------------------------ rows from before this change


def test_the_migration_adds_a_column_and_a_table_and_rewrites_no_row():
    migration = importlib.import_module("assurance.migrations.0087_incident_scope_revision").Migration
    assert [type(operation).__name__ for operation in migration.operations] == ["AddField", "AddField", "CreateModel"]
    for column, name in zip(migration.operations[:2], ("scope_revision", "scope_items"), strict=True):
        assert (column.model_name, column.name, column.field.null, column.field.has_default()) == (
            "recoveryrecord", name, True, False,
        )


def test_rows_from_before_this_change_are_not_rewritten_and_read_scope_not_declared():
    finding = _incident()
    owner = finding.deployment.owner
    _accepted(finding)
    # As migration 0087 leaves a recovery accepted before it: no step names a revision,
    # and none is declared. Written past the guards, as only a migration is.
    RecoveryRecord._base_manager.filter(finding=finding).update(scope_revision=None, scope_items=None)
    IncidentScopeRevision._base_manager.filter(finding=finding).delete()
    before = _history(finding)
    assert (before[-1]["state"], before[-1]["release"]) == (st.RECOVERY_ACCEPTED, st.PASS)

    read = _read(finding)

    assert read["scope_revision"] is None
    assert all(step["scope_revision"] is None and step["scope_gaps"] == [NOT_DECLARED] for step in read["steps"])
    assert read["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
    assert read["steps"][-1]["gaps"] == [NOT_DECLARED]
    assert read["steps"][-1]["recorded"] == {"state": st.RECOVERY_ACCEPTED, "gaps": [], "release": st.PASS}
    assert {step["scope_items"] for step in read["steps"]} == {None}
    # A step that was never a recovered state reads as it was recorded.
    assert [step["state"] for step in read["steps"][:3]] == [step["state"] for step in before[:3]]
    assert _history(finding) == before, "a read rewrites nothing"

    # Declaring the scope records no step; the steps recorded under it do.
    declare_scope(finding)
    assert _read(finding)["current"]["release"] == st.AUDIT_INCOMPLETE
    again = rr.record(finding, by=owner, accept_until=_until())
    assert _states(again) == [st.UNDER_INVESTIGATION, st.REPAIR_PROPOSED, st.REPAIR_TESTED, st.RECOVERY_ACCEPTED]
    assert {step.scope_revision for step in again} == {1} and again[-1].release == st.PASS
    assert _history(finding)[:4] == before


def test_a_scope_revision_that_cannot_be_read_is_caution_never_ok():
    finding = _incident()
    owner = finding.deployment.owner
    _accepted(finding)
    # A revision whose items cannot be read, written past every guard.
    IncidentScopeRevision._base_manager.bulk_create(
        [IncidentScopeRevision(finding=finding, revision=2, supersedes=1, items=[{"kind": "asset"}], reason="x")]
    )

    read = _read(finding)
    assert read["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
    assert read["steps"][-1]["gaps"] == ["scope:unreadable"]
    # What the scope gained and lost is not known, and each read says so beside the gap:
    # never an empty list, which would say that nothing was removed.
    assert read["scope_revision"] == 2 and read["scope_removed"] is None
    first, unreadable = scope.finding_scope(finding)["revisions"]
    assert (first["added"], first["removed"]) == ([scopes.item(scopes.asset(finding.deployment))], [])
    assert (unreadable["added"], unreadable["removed"]) == (None, None)
    # And nothing a step can link answers it: no step is recorded, and none recovers.
    before = _history(finding)
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=owner, accept_until=_until())
    assert refused.value.code == "nothing_moved" and "scope:unreadable" in str(refused.value)
    assert _history(finding) == before
    # A step of an incident whose recovery is still open is held back by it all the same.
    other = _incident("still-open")
    declare_scope(other)
    IncidentScopeRevision._base_manager.bulk_create(
        [IncidentScopeRevision(finding=other, revision=2, supersedes=1, items=[{"kind": "asset"}], reason="x")]
    )
    _repaired_and_tested(other)
    held = rr.record(other, by=other.deployment.owner, body={"coverage": COVERED}, accept_until=_until())[-1]
    assert (held.state, held.gaps, held.release) == (st.REPAIR_TESTED, ["scope:unreadable"], st.AUDIT_INCOMPLETE)
    assert (held.scope_revision, held.scope_items) == (2, _UNKNOWN)
    assert _read(other)["steps"][-1]["scope_items"] == _UNKNOWN
    # With no scope declared at all, nothing is known of what one gained or lost.
    undeclared = _incident("undeclared")
    (opened,) = rr.record(undeclared)
    assert (opened.scope_revision, opened.scope_items) == (None, _UNKNOWN)
    assert (_read(undeclared)["scope_revision"], _read(undeclared)["scope_removed"]) == (None, None)


# ---------------------------------------------------------------------- the routes


def _person(name, role=User.Roles.ADMIN):
    return User.objects.create_user(username=name, password="x", role=role)


def _as(person):
    client = APIClient()
    client.force_authenticate(user=person)
    return client


def _scope_url(finding):
    return f"/api/assurance/findings/{finding.uuid}/scope-revisions/"


def _step_url(finding):
    return f"/api/assurance/findings/{finding.uuid}/recovery-record/"


def _accept():
    return {"until": (timezone.now() + timedelta(days=30)).isoformat()}


@pytest.fixture
def world():
    """Deployment A, owned by an admin, with an incident whose repair is tested and two
    routes; B, owned by someone else, with an incident and a route; and a viewer who owns
    a deployment, an incident and a route of their own."""
    w = SimpleNamespace()
    w.owner, w.admin, w.other_owner = _person("owner"), _person("admin"), _person("other-owner")
    w.viewer = _person("viewer", role=User.Roles.VIEWER)
    w.a = Deployment.objects.create(name="a", owner=w.owner)
    w.b = Deployment.objects.create(name="b", owner=w.other_owner)
    w.mine = Deployment.objects.create(name="viewers-own", owner=w.viewer)

    def incident(dep, name):
        return Finding.objects.create(
            deployment=dep, fingerprint=f"fp-{name}", finding_type="sql_injection", title=name, severity="critical",
            retest_required=True,
        )

    w.incident, w.theirs, w.own = incident(w.a, "a-1"), incident(w.b, "b-1"), incident(w.mine, "mine-1")
    w.primary, w.backup = scopes.asset(w.a, "primary-route"), scopes.asset(w.a, "backup-route")
    w.their_route, w.own_route = scopes.asset(w.b, "their-route"), scopes.asset(w.mine, "own-route")
    _repaired_and_tested(w.incident)
    return w


def test_the_scope_route_records_the_next_revision_for_an_admin_and_names_the_caller(world):
    body = scopes.body(world.incident, world.primary, reason="what the scan reached")
    first = _as(world.admin).post(_scope_url(world.incident), body, format="json")

    assert first.status_code == 201, first.content
    answer = first.json()
    assert (answer["finding"], answer["deployment"], answer["current"]) == (
        str(world.incident.uuid), str(world.a.uuid), 1,
    )
    (served,) = answer["revisions"]
    assert (served["revision"], served["supersedes"], served["current"], served["declared_by"]) == (1, None, True, "admin")
    assert served["items"] == [{"kind": "asset", "ref": str(world.primary.uuid), "asset_kind": "gateway"}]
    assert served["reason"] == "what the scan reached" and [e["uuid"] for e in served["evidence"]] == body["evidence"]

    # Who declared it is the signed-in caller; a body that names anyone, or a number, is refused.
    wider = scopes.body(world.incident, world.primary, world.backup, reason="a backup route in the firewall export")
    for extra in ({"declared_by": "owner"}, {"revision": 9}, {"supersedes": 1}):
        refused = _as(world.admin).post(_scope_url(world.incident), {**wider, **extra}, format="json")
        assert (refused.status_code, refused.json()["code"]) == (400, "not_posted"), extra
    # A reason that is not one printable line is refused, and the answer does not repeat it.
    refused = _as(world.admin).post(_scope_url(world.incident), {**wider, "reason": "found\nHIDDEN-LINE"}, format="json")
    assert (refused.status_code, refused.json()["code"]) == (400, "malformed")
    assert "HIDDEN-LINE" not in refused.content.decode()
    second = _as(world.owner).post(_scope_url(world.incident), wider, format="json")
    assert second.status_code == 201, second.content
    assert second.json()["revisions"][0]["declared_by"] == "owner"
    again = _as(world.owner).post(_scope_url(world.incident), wider, format="json")
    assert (again.status_code, again.json()["code"]) == (409, "nothing_changed")

    read = _as(world.owner).get(_scope_url(world.incident))
    assert read.status_code == 200, read.content
    one, two = read.json()["revisions"]
    assert read.json()["current"] == 2 and one == {**served, "current": False}
    assert (two["supersedes"], two["added"], two["removed"]) == (1, [scopes.item(world.backup)], [])
    assert len(_revisions(world.incident)) == 2


def test_a_revision_is_declared_by_an_admin_only_and_read_by_whoever_reads_the_finding(world):
    own = scopes.body(world.own, world.own_route)
    assert _as(world.viewer).post(_scope_url(world.own), own, format="json").status_code == 403
    assert APIClient().post(_scope_url(world.own), own, format="json").status_code in (401, 403)
    assert APIClient().get(_scope_url(world.own)).status_code in (401, 403)
    assert _revisions(world.own) == []
    for method in ("put", "patch", "delete"):
        assert getattr(_as(world.admin), method)(_scope_url(world.own), own, format="json").status_code == 405
    assert _as(world.admin).post(_scope_url(world.own), own, format="json").status_code == 201
    read = _as(world.viewer).get(_scope_url(world.own))
    assert read.status_code == 200 and read.json()["current"] == 1


def test_a_scope_the_person_cannot_read_is_answered_as_one_that_does_not_exist(world):
    declare_scope(world.theirs, world.their_route)
    before = _revisions(world.theirs)
    viewer = _as(world.viewer)
    absent = f"/api/assurance/findings/{uuid.uuid4()}/scope-revisions/"
    body = scopes.body(world.own, world.own_route)
    for call in (lambda url: viewer.get(url), lambda url: viewer.post(url, body, format="json")):
        refused, missing = call(_scope_url(world.theirs)), call(absent)
        assert refused.status_code == missing.status_code == 404
        assert refused.json() == missing.json()
    assert _revisions(world.theirs) == before


def test_another_deployments_item_is_refused_through_the_route_as_one_that_does_not_exist(world):
    own = scopes.body(world.incident, world.primary)
    said = []
    for ref in (str(world.their_route.uuid), str(uuid.uuid4())):
        body = {**own, "items": [*own["items"], {"kind": "asset", "ref": ref}]}
        refused = _as(world.admin).post(_scope_url(world.incident), body, format="json")
        assert (refused.status_code, refused.json()["code"]) == (400, "unknown_link"), refused.content
        said.append(refused.json()["detail"].replace(ref, "<ref>"))
    assert said[0] == said[1]
    theirs = str(scopes.evidence_of(world.theirs).uuid)
    refused = _as(world.admin).post(_scope_url(world.incident), {**own, "evidence": [theirs]}, format="json")
    assert (refused.status_code, refused.json()["code"]) == (400, "unknown_link")
    assert _revisions(world.incident) == []


def test_the_recovery_record_reads_carry_each_steps_scope_revision_and_the_current_one(world):
    admin, owner = _as(world.admin), _as(world.owner)
    assert admin.post(_step_url(world.theirs), {}, format="json").status_code == 201
    assert admin.post(_scope_url(world.incident), scopes.body(world.incident, world.primary), format="json").status_code == 201
    accepted = owner.post(_step_url(world.incident), {"coverage": COVERED, "accept": _accept()}, format="json")
    assert accepted.status_code == 201, accepted.content
    assert [(s["state"], s["scope_revision"]) for s in accepted.json()["steps"]][-1] == (st.RECOVERY_ACCEPTED, 1)

    one = owner.get(_step_url(world.incident)).json()
    assert one["scope_revision"] == 1 and {s["scope_revision"] for s in one["steps"]} == {1}
    assert one["current"] == {"version": 4, "state": st.RECOVERY_ACCEPTED, "release": st.PASS}

    # The scope widens, through the route. Both reads stop showing it as recovered.
    wider = scopes.body(world.incident, world.primary, world.backup, reason="a backup route in the firewall export")
    assert admin.post(_scope_url(world.incident), wider, format="json").status_code == 201
    one = owner.get(_step_url(world.incident)).json()
    (listed,) = owner.get(f"/api/assurance/deployments/{world.a.uuid}/recovery-records/").json()["incidents"]
    for read in (one, listed):
        assert read["scope_revision"] == 2 and read["scope_removed"] == []
        assert read["current"] == {"version": 4, "state": st.REPAIR_TESTED, "release": st.AUDIT_INCOMPLETE}
        last = read["steps"][-1]
        assert (last["scope_revision"], last["gaps"]) == (1, [_added(2, world.backup)])
        assert not any(state in rr.RECOVERED or release == st.PASS for state, release in _standing(read))
    assert one["steps"] == listed["steps"]
    # Another deployment's incident has its own scope: none declared.
    (theirs,) = admin.get(f"/api/assurance/deployments/{world.b.uuid}/recovery-records/").json()["incidents"]
    assert theirs["scope_revision"] is None and theirs["steps"][0]["scope_gaps"] == [NOT_DECLARED]

    # An empty step, the owner's new acceptance with it, moves nothing: a 409 that names
    # the item still open. With evidence that names the item the next steps are recorded
    # under the new revision, and answered as the read serves them.
    empty = owner.post(_step_url(world.incident), {"accept": _accept()}, format="json")
    assert (empty.status_code, empty.json()["code"]) == (409, "nothing_moved"), empty.content
    assert _added(2, world.backup) in empty.json()["detail"]
    proof = scopes.evidence_naming(world.backup)
    again = owner.post(
        _step_url(world.incident), {"evidence": [str(proof.uuid)], "accept": _accept()}, format="json"
    )
    assert again.status_code == 201, again.content
    assert [(s["state"], s["scope_revision"]) for s in again.json()["steps"]] == [
        (st.UNDER_INVESTIGATION, 2), (st.REPAIR_PROPOSED, 2), (st.REPAIR_TESTED, 2), (st.RECOVERY_ACCEPTED, 2),
    ]
    assert owner.get(_step_url(world.incident)).json()["current"] == {
        "version": 8, "state": st.RECOVERY_ACCEPTED, "release": st.PASS,
    }


def test_a_read_issues_one_statement_for_the_revisions_however_many_incidents_and_steps(django_assert_num_queries):
    first = _incident()
    dep = first.deployment
    second = Finding.objects.create(
        deployment=dep, fingerprint="fp-second", finding_type="sql_injection", title="SQLi", severity="critical"
    )
    primary, backup = scopes.asset(dep, "primary-route"), scopes.asset(dep, "backup-route")
    for finding in (first, second):
        declare_scope(finding, primary)
        rr.record(finding)
    declare_scope(first, primary, backup)
    declare_scope(first, backup, by=first.deployment.owner)

    fresh = Finding.objects.select_related("deployment").get(pk=first.pk)
    with django_assert_num_queries(1):
        assert len(scope.finding_scope(fresh)["revisions"]) == 3
    with django_assert_num_queries(2):
        assert rr.finding_record(fresh)["scope_revision"] == 3
    with django_assert_num_queries(4):
        listed = rr.deployment_records(dep, offset=0, page_size=50)
    assert [incident["scope_revision"] for incident in listed["incidents"]] == [3, 1]


# --------------------------------------------- its class, and nothing a stop reads


def test_the_scope_route_declares_its_operation_class_and_is_no_stop():
    route = "finding-scope-revisions"
    assert degraded.ROUTES[route] == {"GET": degraded.EVIDENCE_READ, "POST": degraded.EFFECT}
    assert degraded.class_of(route, "GET") == degraded.EVIDENCE_READ
    assert degraded.class_of(route, "POST") == degraded.EFFECT
    assert route not in stops.STOP_ROUTES and route not in stops.EXEMPT_ROUTES
    assert set(stops.NOT_STOPS[route]) == {"GET", "POST"}


def test_the_decision_reads_no_scope_and_no_recovery_record():
    watched = set(signals.DECISION_INPUTS) | set(signals.DECISION_FANOUT_INPUTS)
    assert not watched & {"assurance.IncidentScopeRevision", "assurance.RecoveryRecord"}


def test_nothing_on_a_stop_path_imports_the_scope_and_the_scope_imports_nothing_that_can_wait():
    """The stop, pause and revoke paths (safety, failsafe) import nothing of the scope or
    of the recovery record. The scope module does load with the URLconf, as the recovery
    record that reads it does; at import it brings in the standard library, Django and
    Mythos-Core's scope words (``mythos_core.scope``: data and predicates), and nothing
    else: nothing that reads a key or the network, starts a thread or is on a stop path."""
    root = pathlib.Path(__file__).resolve().parent.parent

    def imported(tree, nodes):
        names = set()
        for node in nodes:
            if isinstance(node, ast.Import):
                names |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names |= {node.module or "", *(alias.name for alias in node.names)}
        return names

    for package in ("safety", "failsafe"):
        for path in sorted((root / package).rglob("*.py")):
            # Settings files are never read, by this test or anything else.
            if "migrations" in path.parts or "settings" in path.name:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = imported(tree, ast.walk(tree))
            assert not any("incident_scope" in name or "recovery_record" in name for name in names), path
    module = ast.parse(inspect.getsource(scope))
    at_import = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in module.body if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert at_import == {"__future__", "re", "uuid", "django.db", "django.utils", "mythos_core"}


def test_no_stop_reaches_the_scope_or_the_recovery_record(django_capture_on_commit_callbacks, monkeypatch, settings):
    """A pause by the failsafe service token and by an operator, a demotion, the removal of
    the admin who declared the scope and recorded the recovery, a deactivation, the token
    refresh and a sign-out, with every function of :mod:`assurance.incident_scope` and
    :mod:`assurance.recovery_record` made to fail: each is served as before, and none
    reaches either module."""
    from accounts import views as account_views
    from tests.test_the_backend_sign_in_emits_signed_identity_records import (
        SERVICE_TOKEN,
        _account,
        _admin,
        _deployment,
        _set_role,
        _sign_in,
    )

    dep = _deployment()
    with django_capture_on_commit_callbacks(execute=True):
        _operator, client = _admin("operator")
        service = _account("failsafe-svc", User.Roles.ADMIN)
        demoted = _account("to-demote", User.Roles.ADMIN)
        removed = _account("to-remove", User.Roles.ADMIN)
        deactivated = _account("to-deactivate", User.Roles.ANALYST)
        _account("support-user")
    # Both records name the account that is about to be removed.
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp-stop", finding_type="sql_injection", title="SQLi", severity="critical"
    )
    revision = declare_scope(finding, by=removed)
    (step,) = rr.record(finding, by=removed)
    assert (revision.declared_by, step.recorded_by, step.scope_revision) == (removed, removed, 1)
    refresh = _sign_in("support-user").json()["refresh"]
    signed_out = _sign_in("support-user").json()["refresh"]
    settings.FAILSAFE_SERVICE_TOKEN = SERVICE_TOKEN
    settings.FAILSAFE_SERVICE_USER = service.username

    reached = []

    def tripwire(*args, **kwargs):
        reached.append(args)
        raise AssertionError("a stop reached the scope or the recovery record")

    for module, some in ((scope, {"declare", "check", "holds", "revisions_of"}), (rr, {"derive", "record", "served"})):
        functions = [
            name for name, value in vars(module).items()
            if inspect.isfunction(value) and value.__module__ == module.__name__
        ]
        assert some <= set(functions)
        for name in functions:
            monkeypatch.setattr(module, name, tripwire)
    base = f"/api/assurance/deployments/{dep.uuid}/"
    by_token = APIClient()
    by_token.credentials(HTTP_X_FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN)
    with django_capture_on_commit_callbacks(execute=True):
        assert by_token.post(base + "recompute/", {"paused": True}, format="json").status_code == 200
        assert client.post(base + "recompute/", {"paused": True}, format="json").status_code == 200
        assert _set_role(client, demoted, "viewer").status_code == 200
        assert client.delete(f"/api/accounts/users/{removed.pk}/").status_code == 204
        account_views._deactivate_and_revoke(deactivated)
        assert APIClient().post("/api/token/refresh/", {"refresh": refresh}, format="json").status_code == 200
        assert APIClient().post("/api/token/revoke/", {"refresh": signed_out}, format="json").status_code in (200, 204, 205)
    assert reached == []
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.PAUSED
    # The removal nulled who declared and who recorded, through the base manager.
    assert IncidentScopeRevision._base_manager.get(pk=revision.pk).declared_by_id is None
    assert RecoveryRecord._base_manager.get(pk=step.pk).recorded_by_id is None
