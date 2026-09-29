"""Round 5 (B1, B2, item 8): a person's stop is never lifted by removing the person,
names the person's own act wherever it is carried, and carries no confidence.

B2. Whether a claim's reading is a person's was read off ``ClaimEvent.actor``, and
that foreign key is ``SET_NULL``: removing an operator over HTTP (``DELETE
/api/accounts/users/<id>/``, 204) turned every stop they had made into the
machine's reading. The next recompute found the reading moved and superseded the
version, and the new one opened at the deriver's VERIFIED 0.88 -- the stop lifted,
and no event named anyone. The event now records, when it is written, that a person
made it and the name their account had (``by_person``, ``actor_username``;
migration 0047 fills both for every event whose account is still there), and every
"is this a person's move" check reads that.

B1. A carried stop's note was the previous carried note plus "[carried from ...]",
clipped to 500 characters: a stop with a long note carried with no "carried from"
at all, and along a chain of drifts the version it came from stopped being named
from the fourth carry on. The carried event now points at the person's own act
(``carried_from``) and its note is that act's note -- clipped to leave room -- and a
suffix that is never clipped.

Item 8. A person's CONTRADICTED kept the machine's confidence (0.88), lost it when
carried to a new version, and got it back on the next refresh. A stop -- the
deriver's or a person's -- carries no confidence, on every version.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from assurance import claims as claims_module
from assurance.claims import apply_claim_transition, derive_claims
from assurance.models import Asset, AssuranceClaim, ClaimEvent
from tests.test_every_writer_decides_from_the_row_it_writes import _client, _deployment, _drift, _person
from tests.test_spine_evidence_audit import _access_claim, _current

User = get_user_model()
Status = AssuranceClaim.ClaimStatus


def _contradict(client, claim, note):
    response = client.post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "contradicted", "note": note}, format="json"
    )
    assert response.status_code == 200, response.content
    return response


def _recompute(client, dep):
    response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/", {}, format="json")
    assert response.status_code == 200, response.content
    return response.json()


def _stop_event(claim):
    return claim.events.filter(by_person=True).order_by("-pk").first()


# ---------------------------------------------------------------------------
# B2: removing the person lifts nothing
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("remove, drift", [(False, False), (True, False), (True, True)], ids=["b2a-kept", "b2b-removed", "b2c-removed-then-drift"])
def test_removing_the_operator_who_stopped_a_claim_lifts_nothing(remove, drift):
    boss = _client(_person("boss"))
    alice = _person("alice")
    dep = _deployment("b2")
    claim = _access_claim(dep)
    _contradict(_client(alice), claim, "it reaches prod secrets")
    if remove:
        response = boss.delete(f"/api/accounts/users/{alice.pk}/")
        assert response.status_code == 204, response.content
        assert not User.objects.filter(pk=alice.pk).exists()
    if drift:
        _drift(dep, "x1")

    counts = _recompute(boss, dep)

    current = _current(dep)
    assert current.status == Status.CONTRADICTED, counts
    assert current.confidence is None
    assert (current.pk == claim.pk) is (not drift)
    assert claims_module._status_set_by_a_person(current)
    event = _stop_event(current)
    assert event.to_status == Status.CONTRADICTED
    assert event.actor_username == alice.username
    assert event.actor_id == (None if remove else alice.pk)
    # Served as the person's, named as the account was named when it acted.
    served = boss.get(f"/api/assurance/claims/{current.uuid}/events/").json()
    stops = [e for e in served if e["to_status"] == Status.CONTRADICTED and e["attribution"]["kind"] == "account"]
    assert stops, served
    assert stops[-1]["actor"] == alice.username
    assert stops[-1]["attribution"]["account"] == alice.username
    assert stops[-1]["attribution"]["account_removed"] is remove


@pytest.mark.django_db
def test_a_removed_operators_stop_is_still_lifted_only_by_a_person():
    boss = _client(_person("boss"))
    alice = _person("alice")
    dep = _deployment("b2-lift")
    _contradict(_client(alice), _access_claim(dep), "leaks")
    boss.delete(f"/api/accounts/users/{alice.pk}/")
    for name in ("y1", "y2"):
        _drift(dep, name)
        _recompute(boss, dep)
        assert _current(dep).status == Status.CONTRADICTED

    apply_claim_transition(_current(dep), Status.UNKNOWN, actor=_person("bob"), note="re-checked; lifting")

    assert _current(dep).status == Status.UNKNOWN


@pytest.mark.django_db
def test_every_event_an_account_makes_is_a_persons_and_every_machine_event_is_not():
    dep = _deployment("b2-flags")
    claim = _access_claim(dep)
    person = _person("carol")
    event = apply_claim_transition(claim, Status.CONTRADICTED, actor=person, note="n")

    assert event.by_person is True and event.actor_username == person.username
    derived = claim.events.order_by("pk").first()
    assert derived.actor_id is None and derived.by_person is False and derived.actor_username == ""


# ---------------------------------------------------------------------------
# Migration 0047: forward, back, forward
# ---------------------------------------------------------------------------


_BEFORE = ("assurance", "0046_claim_audit_weighing")
_AFTER = ("assurance", "0047_claim_event_person_snapshot")


def _migrate(target):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate([target])


def _columns():
    with connection.cursor() as cursor:
        return {c.name for c in connection.introspection.get_table_description(cursor, ClaimEvent._meta.db_table)}


@pytest.mark.django_db(transaction=True)
def test_the_snapshot_migration_names_every_persons_event_whose_account_is_there_and_reverses_cleanly():
    dep = _deployment("mig")
    claim = _access_claim(dep)
    kept, gone = _person("kept"), _person("gone")
    kept_event = apply_claim_transition(claim, Status.CONTRADICTED, actor=kept, note="kept's stop")
    gone_event = apply_claim_transition(claim, Status.REVOKED, actor=gone, note="gone's withdrawal")
    machine_event = claim.events.order_by("pk").first()
    assert machine_event.actor_id is None
    head = MigrationExecutor(connection).loader.graph.leaf_nodes("assurance")[0]
    try:
        _migrate(_BEFORE)
        assert not {"by_person", "actor_username", "carried_from_id"} & _columns()
        # At 0046 an account is removed: its event's actor is nulled, and nothing else
        # on the row says a person made it.
        with connection.cursor() as cursor:
            cursor.execute(f"UPDATE {ClaimEvent._meta.db_table} SET actor_id = NULL WHERE id = %s", [gone_event.pk])

        _migrate(_AFTER)

        assert {"by_person", "actor_username", "carried_from_id"} <= _columns()
        kept_event.refresh_from_db()
        gone_event.refresh_from_db()
        machine_event.refresh_from_db()
        assert (kept_event.by_person, kept_event.actor_username) == (True, kept.username)
        # Removed before the snapshot existed: nothing is left to copy (the loss 0047 stops).
        assert (gone_event.by_person, gone_event.actor_username) == (False, "")
        assert (machine_event.by_person, machine_event.actor_username) == (False, "")
    finally:
        _migrate(head)
    assert "by_person" in _columns()


# ---------------------------------------------------------------------------
# B1: a carried stop names the person's own act, never clipped
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("note_length, drifts", [(29, 5), (535, 5)], ids=["short-note", "535-char-note"])
def test_a_stop_carried_along_a_chain_of_drifts_names_its_predecessor_and_the_persons_own_act(note_length, drifts):
    person = _person("dpo")
    admin = _client(_person("admin"))
    dep = _deployment("b1")
    first = _access_claim(dep)
    note = ("Confirmed by the customer's DPO on the call: the replica is outside the approved boundary; " * 10)[:note_length]
    _contradict(_client(person), first, note)
    original = _stop_event(first)
    assert original.note.strip() == note.strip()

    previous = first
    for n in range(1, drifts + 1):
        _drift(dep, f"x{n}")
        _recompute(admin, dep)
        current = _current(dep)
        assert current.pk != previous.pk
        assert current.status == Status.CONTRADICTED
        carried = _stop_event(current)
        assert carried.carried_from_id == original.pk, f"carry {n} points at a copy, not the person's act"
        assert carried.actor_id == person.pk and carried.actor_username == person.username
        assert f"[carried from {previous.uuid}:" in carried.note, f"carry {n} does not name its predecessor"
        assert str(original.uuid) in carried.note and str(first.uuid) in carried.note
        assert carried.note.count("[carried from") == 1, "a chain of suffixes"
        assert carried.note.endswith("no evidence and no re-derive lifts it.]"), "the attribution was clipped"
        assert carried.note.startswith(note.strip()[:20])
        assert len(carried.note) <= 500
        previous = current


# ---------------------------------------------------------------------------
# Item 8: a stop carries no confidence, on any version
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_a_persons_stop_reads_no_confidence_on_every_version_as_the_derivers_does():
    admin = _client(_person("admin"))
    # The control: the deriver reads CONTRADICTED (a tool declares `shell`).
    control_dep = _deployment("conf-control")
    _access_claim(control_dep)
    Asset.objects.filter(deployment=control_dep, identifier="reporter").update(metadata={"permissions": ["shell"]})
    derive_claims(control_dep)
    control = _current(control_dep)
    assert control.status == Status.CONTRADICTED and control.confidence is None

    dep = _deployment("conf")
    claim = _access_claim(dep)
    assert claim.confidence == 0.88
    _contradict(_client(_person("stopper")), claim, "stop")
    seen = [_current(dep).confidence]
    _recompute(admin, dep)  # refreshed in place
    seen.append(_current(dep).confidence)
    _drift(dep, "late")
    _recompute(admin, dep)  # carried to a new version
    seen.append(_current(dep).confidence)
    _recompute(admin, dep)  # refreshed again
    seen.append(_current(dep).confidence)

    assert _current(dep).status == Status.CONTRADICTED
    assert seen == [None, None, None, None]


@pytest.mark.django_db
def test_a_withdrawal_reads_no_confidence():
    dep = _deployment("conf-revoke")
    claim = _access_claim(dep)
    apply_claim_transition(claim, Status.REVOKED, actor=_person(), note="withdrawn")
    assert _current(dep).confidence is None
