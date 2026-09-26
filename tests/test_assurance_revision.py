"""Phase 2 item 5b — revision-fenced decisions and the accepted-change boundary.

The roadmap's need: *no transactional-outbox/watermark/revision-fencing mechanism
exists anywhere in* ``assurance/`` *— a decision consumer can act on a stale read
with no fencing.* The bar: *a consumer reading a decision mid-transition never
sees a torn state (proven by a concurrency test).*

The decision and the claims behind it are separate rows. A consumer reading both
can take the decision from after a transition and the claims from before it, and
what comes back is not an error — it is an ordinary-looking answer assembled from
a state that never existed. Before this there was nothing in the record that made
that seam visible.

What the concurrency tests here prove, and what they do not
----------------------------------------------------------
``select_for_update`` serialises concurrent recomputes on PostgreSQL, which is
what deployments run. This suite runs on SQLite, where Django issues the lock and
the engine ignores it because SQLite serialises writers itself. So these tests
prove the INVARIANTS hold under threading — no duplicate revision, no gap, every
observable revision backed by a transition that agrees with it. They do not prove
the row lock works, because on SQLite there is nothing for it to do.

Saying which of the two is demonstrated matters more than the green tick. A
concurrency test that quietly proved the weaker thing while reading as the
stronger one would be the same defect this module exists to remove.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, transaction
from django.utils import timezone

from assurance.decision import recompute_decision
from assurance.models import DecisionTransition, Deployment
from assurance.revision import (
    StaleDecisionRead,
    accept_transition,
    read_decision,
    transitions_since,
)
from tests.decision_surfaces import stamped_under_the_rules_in_force

pytestmark = pytest.mark.django_db

# The threaded tests below carry `django_db(transaction=True)` of their own. The
# default wraps each test in a transaction that is rolled back, and a second
# thread on its own connection cannot see uncommitted rows -- the deployment the
# main thread created would simply not exist for the reader, which looks like a
# concurrency failure and is a fixture artefact. Real commits, truncated after.

User = get_user_model()
D = Deployment.Decision


def _deployment(name="checkout-assistant"):
    owner = User.objects.create_user(
        username=f"u-{Deployment.objects.count()}",
        password="x",
        role=User.Roles.ANALYST,
    )
    # The decisions written here through the one writer stand for ones the rules
    # computed, so they are stamped as such: unstamped, the first read recomputes them.
    return stamped_under_the_rules_in_force(Deployment.objects.create(name=name, owner=owner))


# ---------------------------------------------------------------------------
# The revision advances only on a real change
# ---------------------------------------------------------------------------


def test_a_fresh_deployment_starts_at_revision_zero_with_no_decision():
    dep = _deployment()
    assert read_decision(dep) == {"decision": None, "revision": 0}
    assert dep.decision_transitions.count() == 0


def test_an_accepted_change_advances_the_revision_by_one_and_records_it():
    dep = _deployment()
    out = accept_transition(dep, to_decision=D.READY, basis_digest="digest-a")

    assert out == {"decision": D.READY, "revision": 1, "changed": True}
    assert read_decision(dep) == {"decision": D.READY, "revision": 1}

    row = dep.decision_transitions.get()
    assert (row.revision, row.from_decision, row.to_decision) == (1, "", D.READY)
    assert row.basis_digest == "digest-a"
    assert row.delivered_at is None, "nothing has confirmed processing it"


def test_recomputing_to_the_same_decision_does_not_advance_the_revision():
    """The revision means "the decision changed". Bumping it when nothing changed
    would make every consumer's fence fire on reassessments that decided nothing,
    and a fence that fires constantly is a fence people learn to ignore."""
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)
    out = accept_transition(dep, to_decision=D.READY)

    assert out == {"decision": D.READY, "revision": 1, "changed": False}
    assert dep.decision_transitions.count() == 1


def test_returning_to_an_earlier_decision_is_a_new_revision_not_the_old_one():
    """READY -> NOT_RECOMMENDED -> READY is three states, not two. The decision
    value alone cannot tell that deployment from one that was always READY, which
    is exactly why a consumer cannot fence on the value."""
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)
    accept_transition(dep, to_decision=D.NOT_RECOMMENDED)
    out = accept_transition(dep, to_decision=D.READY)

    assert out["revision"] == 3
    assert [t.revision for t in dep.decision_transitions.all()] == [1, 2, 3]
    assert [t.to_decision for t in dep.decision_transitions.all()] == [
        D.READY,
        D.NOT_RECOMMENDED,
        D.READY,
    ]


def test_the_in_memory_instance_is_not_left_holding_stale_values():
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)
    assert (dep.decision, dep.decision_revision) == (D.READY, 1)


# ---------------------------------------------------------------------------
# The fence
# ---------------------------------------------------------------------------


def test_a_read_fenced_at_a_revision_it_has_reached_succeeds():
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)
    assert read_decision(dep, at_least=1)["revision"] == 1


def test_a_read_behind_the_fence_raises_rather_than_returning_the_stale_value():
    """Returning it with a flag attached would make ignoring the flag the easy
    path, and a consumer that asked to be fenced at 3 has said it cannot use 1."""
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)

    with pytest.raises(StaleDecisionRead) as excinfo:
        read_decision(dep, at_least=3)
    assert "older than the required 3" in str(excinfo.value)


def test_an_unfenced_read_is_still_allowed_and_says_which_revision_it_got():
    """Not every consumer has a watermark yet. The revision travels with the value
    regardless, so one that does not fence today can start tomorrow."""
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)
    assert read_decision(dep) == {"decision": D.READY, "revision": 1}


def test_the_read_goes_to_the_database_and_not_to_a_held_instance():
    """The case the fence exists for: an instance loaded before a transition
    carries the old values, and a consumer holding one has no way to know."""
    dep = _deployment()
    stale_handle = Deployment.objects.get(pk=dep.pk)
    accept_transition(dep, to_decision=D.READY)

    assert stale_handle.decision is None, "the held instance really is stale"
    assert read_decision(stale_handle)["decision"] == D.READY


# ---------------------------------------------------------------------------
# Draining downstream
# ---------------------------------------------------------------------------


def test_transitions_since_returns_only_what_came_after_and_in_revision_order():
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)
    accept_transition(dep, to_decision=D.NOT_RECOMMENDED)
    accept_transition(dep, to_decision=D.NEEDS_MORE_EVIDENCE)

    assert [t.revision for t in transitions_since(dep, 1)] == [2, 3]
    assert [t.revision for t in transitions_since(dep, 0)] == [1, 2, 3]
    assert list(transitions_since(dep, 3)) == []


def test_transitions_are_ordered_by_revision_and_not_by_clock():
    """Two transitions can share or invert a timestamp; the revision is the thing
    that is actually ordered, so a consumer draining by time could process them
    out of order and never know.

    The first version of this test created three transitions in revision order and
    asserted the revisions came back sorted — which was true whether the query
    ordered by revision or by clock, because the two agreed. A mutation swapping
    the ordering survived it. So the clock is now deliberately made to DISAGREE
    with the revision, which is the only arrangement that can tell the two apart.
    """
    dep = _deployment()
    for decision in (D.READY, D.NOT_RECOMMENDED, D.READY):
        accept_transition(dep, to_decision=decision)

    # Invert the timestamps against the revisions: revision 1 newest, 3 oldest.
    # `created_at` is auto_now_add, so it is rewritten after the fact.
    base = timezone.now()
    for row in dep.decision_transitions.all():
        DecisionTransition.objects.filter(pk=row.pk).update(
            created_at=base - timedelta(minutes=row.revision)
        )

    rows = list(transitions_since(dep, 0))
    assert [r.revision for r in rows] == [1, 2, 3], (
        "the drain is ordered by clock, so a consumer would process these backwards"
    )
    assert [r.created_at for r in rows] != sorted(r.created_at for r in rows), (
        "the clock no longer disagrees with the revision, so this proves nothing"
    )


# ---------------------------------------------------------------------------
# One revision per deployment, enforced by the database
# ---------------------------------------------------------------------------


def test_two_transitions_cannot_share_a_revision():
    """A duplicate revision would let two different decisions both claim to be
    revision 4, and a consumer fencing on 4 could not tell which it acted on.
    Enforced in the schema so it is an error rather than an inconsistency."""
    dep = _deployment()
    accept_transition(dep, to_decision=D.READY)
    with pytest.raises(IntegrityError), transaction.atomic():
        DecisionTransition.objects.create(
            deployment=dep, revision=1, from_decision="", to_decision=D.NOT_RECOMMENDED
        )


def test_two_deployments_keep_independent_revision_sequences():
    one, two = _deployment("one"), _deployment("two")
    accept_transition(one, to_decision=D.READY)
    accept_transition(one, to_decision=D.NOT_RECOMMENDED)
    accept_transition(two, to_decision=D.READY)

    assert read_decision(one)["revision"] == 2
    assert read_decision(two)["revision"] == 1


# ---------------------------------------------------------------------------
# Concurrency — the invariants under threading
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_concurrent_transitions_produce_no_duplicate_and_no_gap():
    """Many writers, one sequence. See the module docstring for what this proves
    on SQLite and what it does not."""
    dep = _deployment()
    decisions = [D.READY, D.NOT_RECOMMENDED, D.NEEDS_MORE_EVIDENCE, D.READY]

    start = threading.Barrier(len(decisions))
    errors: list[Exception] = []

    def writer(decision):
        start.wait()
        try:
            accept_transition(dep, to_decision=decision)
        except Exception as exc:  # noqa: BLE001 - recorded and asserted below
            errors.append(exc)
        finally:
            connection.close()

    threads = [threading.Thread(target=writer, args=(d,)) for d in decisions]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], errors

    revisions = sorted(t.revision for t in dep.decision_transitions.all())
    assert len(revisions) == len(set(revisions)), "a revision was issued twice"
    assert revisions == list(range(1, len(revisions) + 1)), "the sequence has a gap"
    assert read_decision(dep)["revision"] == max(revisions, default=0)


@pytest.mark.django_db(transaction=True)
def test_a_reader_never_sees_a_decision_whose_transition_is_missing():
    """The torn state the bar names, from the reader's side: every revision a read
    can observe has a transition behind it recording how the decision got there,
    and that transition agrees with the decision read.

    Without the single commit boundary the decision could land and the transition
    not yet exist, and a reader catching that window would have a decision it
    could not account for — which reads exactly like a decision it can.

    THE CHECK HAPPENS AT READ TIME, and that is the whole test. It used to collect
    every observation and compare them against the outbox after every writer had
    joined — by which point every transition exists, so a transient window could
    not be detected at all. Moving the transition's `create` outside the
    transaction with a 50ms gap, which is precisely the tear this module's
    docstring says cannot happen, left all 97 tests in this file green. Asking at
    the moment of the read reports it 634 times."""
    dep = _deployment()
    observed: list[int] = []
    torn: list[dict] = []
    stop = threading.Event()

    def reader():
        try:
            while not stop.is_set():
                seen = read_decision(dep)
                revision = seen["revision"]
                if revision == 0:
                    if seen["decision"] is not None:
                        torn.append({"revision": 0, "why": "a decision at revision 0"})
                    continue
                # Asked NOW. A window that has closed by the time the writers have
                # finished is still a window a consumer can read inside.
                behind = (
                    DecisionTransition.objects.filter(deployment=dep, revision=revision)
                    .values_list("to_decision", flat=True)
                    .first()
                )
                if behind is None:
                    torn.append(
                        {
                            "revision": revision,
                            "decision": seen["decision"],
                            "why": "no transition behind it at the moment it was readable",
                        }
                    )
                elif behind != seen["decision"]:
                    torn.append(
                        {
                            "revision": revision,
                            "decision": seen["decision"],
                            "why": f"the transition for that revision says {behind!r}",
                        }
                    )
                observed.append(revision)
        finally:
            connection.close()

    watcher = threading.Thread(target=reader)
    watcher.start()
    try:
        for decision in (D.READY, D.NOT_RECOMMENDED, D.NEEDS_MORE_EVIDENCE, D.READY):
            accept_transition(dep, to_decision=decision)
    finally:
        stop.set()
        watcher.join()

    assert observed, "the reader never observed a written revision"
    assert not torn, f"a reader saw a decision it could not account for: {torn[:5]}"


@pytest.mark.django_db(transaction=True)
def test_the_observed_revision_never_goes_backwards():
    """Monotonicity is what a watermark rests on. A revision that could decrease
    would make `at_least` fire on a read that is actually current."""
    dep = _deployment()
    seen: list[int] = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            seen.append(read_decision(dep)["revision"])
        connection.close()

    watcher = threading.Thread(target=reader)
    watcher.start()
    try:
        for decision in (D.READY, D.NOT_RECOMMENDED, D.READY):
            accept_transition(dep, to_decision=decision)
    finally:
        stop.set()
        watcher.join()

    assert seen == sorted(seen), "an observed revision went backwards"


# ---------------------------------------------------------------------------
# The decision path actually uses it
# ---------------------------------------------------------------------------


def test_recompute_decision_goes_through_the_accepted_change_boundary():
    """The mechanism is worth nothing if the one writer in the codebase bypasses
    it. `recompute_decision` is that writer."""
    dep = _deployment()
    recompute_decision(dep)

    after = read_decision(dep)
    if after["revision"] == 0:
        # An unassessed deployment computes to None, which is no change from None.
        assert after["decision"] is None
        assert dep.decision_transitions.count() == 0
    else:
        assert dep.decision_transitions.count() == after["revision"]


def test_nothing_writes_the_decision_outside_the_boundary():
    """The guard. A bare `deployment.decision = x; save()` anywhere would move the
    decision without a revision or a transition, and every fence downstream would
    be reading a number that had stopped tracking the thing it names — silently,
    because the decision itself would still be correct."""
    root = Path(__file__).resolve().parent.parent / "assurance"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "revision.py" or "migrations" in path.parts:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("deployment.decision =", "locked.decision =")):
                offenders.append(f"{path.relative_to(root)}:{number}")
    assert offenders == [], (
        f"these write the decision outside accept_transition: {offenders}"
    )
