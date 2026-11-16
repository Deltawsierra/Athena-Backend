"""An incident's scope is spelled once, by Mythos-Core, and this backend reads it from there.

SP-3 (``assurance/incident_scope.py``, ``assurance/recovery_record.py``) had to spell four
things the core had no word for: the kinds of scope item, the scope holds, the rule for a
revision's reason, and "a scope revision reopens an accepted recovery". Mythos-Core#80 is
the one spelling (``mythos_core.scope``, on ``mythos_core.provenance``'s prose reason),
with an answer key, ``tests/vectors/provenance-and-scope-v1.json``, in the core's own
repository.

That file is not installed with the core, and no copy of it is kept here. Every expected
value below is asked of the INSTALLED core while the test runs: the commit the pin guard
holds this run to, whose own CI holds that code to the file. No answer is typed in this
file. So a word or a rule that drifts here fails against the core this service runs on,
and a core that moves a word fails here, in the pull request that moves the pin.

What is held:

1. each adopted word is the core's own object, and neither module spells one again;
2. each adopted rule gives the core's answer on every case here (a stored kind, a hold's
   name, a hold that ends with its item, the reopening of an accepted recovery);
3. where this backend is STRICTER it is stricter and never looser: the kinds a revision
   may declare (the two it has a record for, of the core's four) and a reason's length
   (500, of the core's 1000). Everything it accepts the core accepts, with the same answer.

One difference is recorded and not settled here: :data:`CODE_OF_A_REFUSED_REASON`.

Nothing here is on a stop path, and nothing on one reads the scope: the SP-3 suite holds
that (``test_no_stop_reaches_the_scope_or_the_recovery_record``).
"""

from __future__ import annotations

import ast
import inspect

import pytest
from django.contrib.auth import get_user_model
from mythos_core import provenance as core_provenance
from mythos_core import scope as core
from mythos_core import status as st

from assurance import incident_scope as scope
from assurance import recovery_record as rr
from assurance.models import IncidentScopeRevision
from tests import incident_scopes as scopes
from tests.incident_scopes import declare as declare_scope
from tests.test_a_recovery_record_is_derived_from_its_witnesses import _history, _incident, _until
from tests.test_an_incidents_scope_is_versioned_and_no_recovery_outlives_it import _accepted, _restored

User = get_user_model()

#: The code this backend answers when it refuses a reason, by the code the core answers
#: for the same reason. The core tells a missing or blank reason (``reason_required``)
#: from the rest; this backend answers ``malformed`` for both, as SP-3 (#229) does. The
#: two differ in the word only, never in what is refused, so neither is the stricter:
#: which word this backend answers is not decided in this pull request. Held here so
#: that it changes only on purpose.
CODE_OF_A_REFUSED_REASON = {"reason_required": "malformed", "malformed": "malformed"}


def _code(call, *args, refusal):
    """The code ``call(*args)`` is refused with, or None when it is not refused."""
    try:
        call(*args)
    except refusal as exc:
        return exc.code
    return None


# ----------------------------------------------------------------- 1. the words


def test_the_kinds_and_the_holds_are_the_cores_own_objects():
    read = scope._core()
    assert read is core, "the scope reads mythos_core.scope itself, not a copy of it"
    # The kinds a revision may declare are the core's two that this backend has a
    # record for, in the core's order, and each is one of the core's kinds.
    assert scope.kinds() == (core.ASSET, core.WORKFLOW)
    assert all(core.is_scope_item_kind(kind) for kind in scope.kinds())
    assert set(scope.kinds()) < set(core.SCOPE_ITEM_KINDS), "stricter than the core's set, never wider"
    # The two holds that name no item, as each function answers them.
    assert scope.holds(None, []) == [core.NOT_DECLARED]
    assert scope.holds(1, [_rev(1, "a"), _unread(2)]) == [core.UNREADABLE]
    # And the recovery record asks the same module.
    assert rr.core_scope is core


def _spelled(module) -> list[tuple[int, str]]:
    """Every string in ``module``'s code, with its line: not its docstrings or comments."""
    tree = ast.parse(inspect.getsource(module))
    documented = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, documented)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings
    ]


def test_neither_module_spells_a_scope_word_again():
    """A word read from the core and also typed here is two spellings: the typed one is
    what drifts. So the scope module's code holds none of the core's kinds and none of
    its holds, and the recovery record's code no hold. (The recovery record's links
    have fields named for the asset and the workflow they hold; those are stored field
    names of SP-1's, and it compares a kind with the core's word.)"""
    kinds = set(core.SCOPE_ITEM_KINDS)
    prefix = core.NOT_DECLARED.split(":")[0] + ":"
    assert core.UNREADABLE.startswith(prefix) and core.gap(1, core.ASSET, "a").startswith(prefix)

    in_scope = _spelled(scope)
    assert len(in_scope) > 20, "the scan read the module"
    typed = [(line, text) for line, text in in_scope if text in kinds or text.startswith(prefix)]
    assert not typed, f"assurance/incident_scope.py spells a word the core spells: {typed}"

    in_record = _spelled(rr)
    assert len(in_record) > 20
    typed = [(line, text) for line, text in in_record if text.startswith(prefix)]
    assert not typed, f"assurance/recovery_record.py spells a scope hold the core spells: {typed}"
    source = inspect.getsource(rr)
    assert "core_scope.ASSET" in source and "core_scope.WORKFLOW" in source


# ------------------------------------------------- 2. a stored kind, as the core reads it

#: Values a stored item's kind may hold. The core's own kinds come first; the rest are
#: what the core's answer key calls unreadable, and a few more.
KIND_PROBES = [
    *core.SCOPE_ITEM_KINDS, core.UNKNOWN, None, "", "Asset", "assets", "system", "gateway", ["asset"], 1, True,
    " asset", "asset\n",
]


def _rev(number, *refs, kind=None):
    return type("Revision", (), {
        "revision": number, "items": [{"kind": core.ASSET if kind is None else kind, "ref": ref} for ref in refs],
    })()


def _unread(number):
    """A revision whose items cannot be read: one with no kind at all."""
    return type("Revision", (), {"revision": number, "items": [{"ref": "a"}]})()


@pytest.mark.parametrize("kind", KIND_PROBES, ids=repr)
def test_a_stored_kind_is_read_as_the_core_reads_it(kind):
    """A kind the core reads as ``unknown`` makes the scope unreadable, never smaller: the
    item is not dropped, and nothing reads as if it were not there."""
    unknown = core.read_scope_item_kind(kind) == core.UNKNOWN
    assert unknown == (not core.is_scope_item_kind(kind))
    stored = [{"kind": core.ASSET, "ref": "a"}, {"kind": kind, "ref": "b"}]
    keys = scope._keys(stored)
    assert (keys is None) == unknown
    revisions = [_rev(1, "a"), type("Revision", (), {"revision": 2, "items": stored})()]
    if unknown:
        assert scope.since(revisions) is None and scope.removed(revisions) is None
        assert scope.holds(1, revisions) == [core.UNREADABLE]
        assert rr.scope_holds_of(1, revisions, {}, rr.manifest_of(_Finding, None)) == [core.UNREADABLE]
    else:
        assert keys == [(core.ASSET, "a"), (kind, "b")]
        assert scope.holds(1, revisions) == [core.gap(2, kind, "b")]


class _Finding:
    uuid = "00000000-0000-4000-8000-000000000000"


def test_a_revision_declares_only_a_kind_this_backend_has_a_record_for():
    """STRICTER than the core: of its four kinds a revision here declares two. Every
    other value, a core kind or not, is refused, and nothing is looked up for it."""
    a_ref = {core.ASSET: "394c1bd6-7b25-4909-b47e-3aa794c3fa5f", core.WORKFLOW: "refund_approval"}
    assert set(a_ref) == set(scope.kinds())
    for kind in KIND_PROBES:
        declared = type(kind) is str and kind in a_ref
        posted = [{"kind": kind, "ref": a_ref[kind] if declared else "refund_approval"}]
        code = _code(scope._posted, posted, refusal=scope.ScopeRefused)
        assert code == (None if declared else "malformed"), kind
        # What this backend declares, the core calls a kind: never looser than the core.
        assert not declared or core.is_scope_item_kind(kind)
    refused = [kind for kind in core.SCOPE_ITEM_KINDS if kind not in a_ref]
    assert refused, "the core names kinds this backend does not declare, and each was refused above"


# ------------------------------------------------------ 2. a hold, as the core names it

#: (revision, kind, ref): what a hold may be asked to name. The core names some and
#: refuses the rest (a kind that is none of its four, a ref outside its alphabet, a
#: revision it does not count).
HOLD_PROBES = [
    (2, core.ASSET, "394c1bd6-7b25-4909-b47e-3aa794c3fa5f"), (3, core.WORKFLOW, "refund_approval"),
    (2, core.WORKFLOW, "-night-batch"), (12, core.ROUTE, "vendor-modem/M2"), (2, core.IDENTITY, "token:TK4"),
    (1, core.ASSET, "a"), (999_999_999, core.ASSET, "a"),
    (2, "system", "host-1"), (2, core.UNKNOWN, "host-1"), (2, None, "host-1"), (0, core.ASSET, "host-1"),
    ("2", core.ASSET, "host-1"), (True, core.ASSET, "host-1"), (2, core.ASSET, ""), (2, core.ASSET, "host 1"),
    (2, core.ASSET, 7), (1_000_000_000, core.ASSET, "a"), (2, core.ASSET, "x" * 201), (2, core.ASSET, "a\n"),
]


@pytest.mark.parametrize(("revision", "kind", "ref"), HOLD_PROBES, ids=repr)
def test_a_hold_is_named_by_the_core_and_one_it_cannot_name_reads_unreadable(revision, kind, ref):
    refused = _code(core.gap, revision, kind, ref, refusal=core.ScopeError)
    hold = scope.gap(revision, kind, ref)
    if refused is None:
        assert hold == core.gap(revision, kind, ref)
    else:
        # Never as no hold, and never as a spelling the core does not have.
        assert hold == core.UNREADABLE
    assert core.is_scope_hold(hold) and core.read_hold(hold) == hold


def test_some_probe_is_named_and_some_is_refused():
    """Not vacuous: the cases above reach both answers, and every code ``gap`` refuses under."""
    codes = {_code(core.gap, *probe, refusal=core.ScopeError) for probe in HOLD_PROBES}
    assert codes == {None, "unknown_kind", "malformed"}
    assert {core.is_scope_item_kind(kind) for kind in KIND_PROBES} == {True, False}


def test_a_hold_stands_only_while_its_item_is_in_scope_and_every_hold_is_the_cores_spelling():
    """The core's rule for the holds: each item a revision added is named; a later
    revision that removes it ends the hold and is disclosed, never a hold itself; an
    item removed and added again counts from the revision that added it again; a
    revision that only removes takes nothing away."""
    a, b, c = "a", "b", "c"
    cases = [
        # taken under, revisions, what holds a recovered state back
        (None, [], [core.NOT_DECLARED]),
        (None, [_rev(1, a)], [core.NOT_DECLARED]),
        (3, [_rev(1, a), _rev(2, a, b)], [core.NOT_DECLARED]),
        (1, [_rev(1, a)], []),
        (1, [_rev(1, a), _rev(2, a, b)], [core.gap(2, core.ASSET, b)]),
        (2, [_rev(1, a), _rev(2, a, b)], []),
        (1, [_rev(1, a, b), _rev(2, a)], []),
        (1, [_rev(1, a), _rev(2, a, b), _rev(3, a)], []),
        (1, [_rev(1, a), _rev(2, a, b, c), _rev(3, a, b)], [core.gap(2, core.ASSET, b)]),
        (1, [_rev(1, a, b), _rev(2, a), _rev(3, a, b)], [core.gap(3, core.ASSET, b)]),
        (1, [_rev(1, a), _rev(2, a, kind=core.WORKFLOW)], [core.gap(2, core.WORKFLOW, a)]),
        (1, [_rev(1, a), _unread(2)], [core.UNREADABLE]),
        # Two items the core cannot name: unreadable once, and never no hold.
        (1, [_rev(1, a), _rev(2, a, "b 1", "c 2")], [core.UNREADABLE]),
    ]
    for taken_under, revisions, expected in cases:
        holds = scope.holds(taken_under, revisions)
        assert holds == expected, (taken_under, [row.items for row in revisions])
        assert all(core.is_scope_hold(hold) and core.read_hold(hold) == hold for hold in holds)

    # The item that left the scope: no hold, and disclosed with both revision numbers.
    left = [_rev(1, a), _rev(2, a, b), _rev(3, a)]
    assert scope.holds(1, left) == []
    (gone,) = scope.removed(left)
    assert (gone["kind"], gone["ref"], gone["added"], gone["removed"]) == (core.ASSET, b, 2, 3)
    # What a removal would be called is not a hold in the core's spelling, so nothing
    # here can pass one off as a reason to hold or to reopen.
    assert not core.is_scope_hold(core.gap(2, core.ASSET, b).replace(":added:", ":removed:"))


# ------------------------------------------------- 2 and 3. a revision's reason

REASON_PROBES = [
    "the gateway and the refund workflow are named in the report", " the backup route was decommissioned ",
    "Die Leitung war außer Betrieb", "x", "x" * 500, "x" * 501, "x" * 1000, "x" * 1001,
    None, "", "   ", "\t", "first line\nsecond line", "one line\n", "one line\rover it", "a tab\tin it",
    "one line\u0007", "approved by ‮resu eht", "one​line", "nul\x00", 7, ["one line"], b"one line", True,
]


@pytest.mark.parametrize("reason", REASON_PROBES, ids=lambda value: repr(value)[:40])
def test_a_reason_is_the_cores_one_printable_line_and_shorter_here(reason):
    in_core = _code(core.revision_reason, reason, refusal=core.ScopeError)
    here = _code(scope._reason, reason, refusal=scope.ScopeRefused)
    if in_core is not None:
        # Never looser: what the core refuses is refused here, a blank reason included.
        assert here == CODE_OF_A_REFUSED_REASON[in_core]
    elif here is None:
        # What is accepted here the core accepts, and both return it exactly as given.
        assert scope._reason(reason) is reason and core.revision_reason(reason) is reason
        assert len(reason) <= scope._REASON_MOST
    else:
        # Refused here and not by the core: only for this backend's shorter limit.
        assert here == "malformed" and scope._REASON_MOST < len(reason) <= core_provenance.MAX_REASON_LENGTH


def test_the_reason_cases_reach_every_answer_and_the_limit_is_never_above_the_cores():
    assert scope._REASON_MOST <= core_provenance.MAX_REASON_LENGTH
    in_core = {_code(core.revision_reason, reason, refusal=core.ScopeError) for reason in REASON_PROBES}
    assert in_core == {None, "reason_required", "malformed"} == {None, *CODE_OF_A_REFUSED_REASON}
    here = [_code(scope._reason, reason, refusal=scope.ScopeRefused) for reason in REASON_PROBES]
    assert here.count(None) == 5 and scope._reason("x" * scope._REASON_MOST)
    # The stricter limit bites: something the core takes is refused here.
    longer = "x" * (scope._REASON_MOST + 1)
    assert core.revision_reason(longer) == longer and _code(scope._reason, longer, refusal=scope.ScopeRefused)


@pytest.mark.django_db
@pytest.mark.usefixtures("engine_keyring")
def test_every_revision_states_its_reason_the_first_too():
    """The core's rule, through the function that records a revision: no reason, no
    revision, for the first as for a later one. Nothing is recorded by a refusal."""
    finding = _incident()
    primary, backup = scopes.asset(finding.deployment), scopes.asset(finding.deployment, "backup-route")
    for records in ((primary,), (primary, backup)):
        for blank in (None, "", "   "):
            assert _code(core.revision_reason, blank, refusal=core.ScopeError) == "reason_required"
            body = scopes.body(finding, *records, reason=blank)
            before = IncidentScopeRevision._base_manager.filter(finding=finding).count()
            with pytest.raises(scope.ScopeRefused) as refused:
                scope.declare(finding, body=body)
            assert refused.value.code == CODE_OF_A_REFUSED_REASON["reason_required"]
            assert IncidentScopeRevision._base_manager.filter(finding=finding).count() == before
        declare_scope(finding, *records, by=finding.deployment.owner)
    assert IncidentScopeRevision._base_manager.filter(finding=finding).count() == 2


# ---------------------------------- 2. a scope revision reopens an accepted recovery

def _watch(monkeypatch):
    """Every question put to the core's ``check_scope_reopen`` while the test runs, each
    still answered by the core."""
    asked, real = [], core.check_scope_reopen

    def check_scope_reopen(before, after, holds):
        asked.append((before, after, list(holds)))
        return real(before, after, holds)

    monkeypatch.setattr(core, "check_scope_reopen", check_scope_reopen)
    return asked


@pytest.mark.django_db
@pytest.mark.usefixtures("engine_keyring")
def test_a_wider_scope_reopens_an_accepted_recovery_by_the_cores_rule(monkeypatch):
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    accepted = _accepted(finding, primary)[-1]
    asked = _watch(monkeypatch)

    backup = scopes.asset(dep, "backup-route")
    declare_scope(finding, primary, backup, reason="a backup route found in the firewall export")
    hold = core.gap(2, core.ASSET, str(backup.uuid))
    revisions = scope.revisions_of([finding.pk])[finding.pk]
    assert rr.lapsed(accepted, revisions) == [hold]
    assert asked == [], "declaring a scope records no step and asks nothing"

    proof = scopes.evidence_naming(backup)
    someone = User.objects.create_user(username="another-admin", password="x", role=User.Roles.ADMIN)
    again = rr.record(finding, by=someone, body={"evidence": [str(proof.uuid)]})
    reopening = again[0]
    assert (reopening.state, reopening.reopens, reopening.scope_revision) == (
        st.UNDER_INVESTIGATION, str(accepted.uuid), 2,
    )

    # The core was asked about the accepted step and the step that reopens it, with
    # the hold that stands against the accepted one, and about no other step.
    assert asked, "the reopening of an accepted recovery is the core's rule, and it was not asked"
    for before, after, holds in asked:
        assert (before.ref, before.state) == (str(accepted.uuid), st.RECOVERY_ACCEPTED)
        assert (after.ref, after.state, after.reopens) == (str(reopening.uuid), st.UNDER_INVESTIGATION, before.ref)
        assert holds == [hold] and all(core.is_scope_hold(one) for one in holds)
    # S1 still lets nothing follow an accepted recovery: the core's status is unchanged.
    with pytest.raises(st.RecoveryError) as terminal:
        st.check_recovery_step(rr._as_recovery(accepted), rr._as_recovery(reopening))
    assert terminal.value.code == "terminal"

    # What was recorded satisfies the core's rule, and breaks each part of it when changed.
    before, after = rr._as_recovery(accepted), rr._as_recovery(reopening)
    core.check_scope_reopen(before, after, [hold])
    for holds, code in (([], "scope_hold_required"), ([hold.replace(":added:", ":removed:")], "not_a_scope_hold")):
        assert _code(core.check_scope_reopen, before, after, holds, refusal=core.ScopeError) == code
    assert _code(core.check_scope_reopen, before, rr._as_recovery(again[1]), [hold], refusal=core.ScopeError) == "not_a_reopen"


@pytest.mark.django_db
@pytest.mark.usefixtures("engine_keyring")
def test_what_the_core_refuses_of_a_reopen_is_refused_here_and_nothing_is_recorded(monkeypatch):
    """The rule is the core's, so its refusal is this backend's: with its code, and with
    no step recorded."""
    finding = _incident()
    primary = scopes.asset(finding.deployment, "primary-route")
    _accepted(finding, primary)
    backup = scopes.asset(finding.deployment, "backup-route")
    declare_scope(finding, primary, backup, reason="a backup route found in the firewall export")
    proof = scopes.evidence_naming(backup)
    before = _history(finding)

    def refuse(*_args):
        raise core.ScopeError("scope_hold_required", "nothing follows an accepted recovery")

    monkeypatch.setattr(core, "check_scope_reopen", refuse)
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=finding.deployment.owner, body={"evidence": [str(proof.uuid)]})
    assert refused.value.code == "scope_hold_required"
    assert _history(finding) == before


@pytest.mark.django_db
@pytest.mark.usefixtures("engine_keyring")
def test_an_accepted_recovery_whose_scope_still_stands_is_followed_by_nothing(monkeypatch):
    """Without a scope hold nothing follows an accepted recovery, exactly as before: the
    step is refused before the core's reopen rule has anything to answer."""
    finding = _incident()
    _accepted(finding, scopes.asset(finding.deployment, "primary-route"))
    asked = _watch(monkeypatch)
    before = _history(finding)
    with pytest.raises(rr.RecoveryRefused) as refused:
        rr.record(finding, by=finding.deployment.owner, accept_until=_until())
    assert refused.value.code == "terminal" and asked == [] and _history(finding) == before


@pytest.mark.django_db
@pytest.mark.usefixtures("engine_keyring")
def test_a_restricted_restore_is_reopened_by_s1_and_the_cores_scope_rule_is_not_asked(monkeypatch):
    """The core's scope reopen answers for an accepted recovery only: every other state
    is reopened by ``status.check_recovery_step``, which already allows it."""
    finding = _incident()
    dep = finding.deployment
    primary = scopes.asset(dep, "primary-route")
    restored = _restored(finding, primary)[-1]
    asked = _watch(monkeypatch)
    backup = scopes.asset(dep, "backup-route")
    declare_scope(finding, primary, backup, reason="a backup route found in the firewall export")
    proof = scopes.evidence_naming(backup)
    again = rr.record(finding, by=dep.owner, body={"evidence": [str(proof.uuid)]})
    assert (again[0].state, again[0].reopens) == (st.UNDER_INVESTIGATION, str(restored.uuid))
    assert asked == []
    st.check_recovery_step(rr._as_recovery(restored), rr._as_recovery(again[0]))
    hold = core.gap(2, core.ASSET, str(backup.uuid))
    refused = _code(
        core.check_scope_reopen, rr._as_recovery(restored), rr._as_recovery(again[0]), [hold], refusal=core.ScopeError
    )
    assert refused == "not_accepted"
