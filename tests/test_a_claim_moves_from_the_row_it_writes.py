"""SPINE #333, round 3: a claim transition decides from the row as it is committed
at the moment it writes -- and no stop is ever lost to one that read it earlier.

The transition route loaded the claim (``get_object``) BEFORE it opened its
transaction, then decided and wrote from that in-memory row. SQLite takes the
write lock at BEGIN (IMMEDIATE), so a request that arrived while another write
was open read the claim as it was before that write, waited for the lock, and
wrote its decision over it. Round 3 reproduced, over HTTP:

- N2 (natural, no patching): a person's move arriving while a revoke commits.
  Both answered 200 and the claim ended ``partially_verified`` -- the revoke,
  a stop, silently undone.
- R2/R3: the same with a contradiction, and with the window widened.
- R1 / N1: a contradiction addressed to a version a re-derive superseded while
  it was in flight. Widened, it landed on the now-closed version (200) and the
  current version stayed VERIFIED; natural, it was a 400 naming the version to
  stop instead -- either way the claim anything reads stayed un-stopped.

Now every transition re-reads the claim under the write lock and decides from
that row. A stop always lands: on the claim identity's CURRENT version when it
was addressed to a superseded one (recorded as addressed to it), and a
withdrawal stays terminal. A person's move read before a stop or a supersession
committed is refused, 409 "the claim changed; re-read", never written over it.

The races run on the test database file with real threads (``transaction=True``);
where a window is widened, the patch only waits after the real ``get_object``
returns -- nothing else is changed.
"""

from __future__ import annotations

import threading
import time
import uuid
from itertools import count

import pytest
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from rest_framework.test import APIClient

from assurance import views as assurance_views
from assurance import claims as claims_module
from assurance.claims import IllegalClaimTransition, apply_claim_transition, derive_claims
from assurance.models import Asset, AssuranceClaim, ClaimEvent, Deployment
from tests.test_spine_evidence_audit import _access_claim, _current

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType

_names = count()


def _person(prefix="person"):
    # Unique across runs: the threaded tests commit their rows.
    return User.objects.create_user(
        username=f"{prefix}-r3-{next(_names)}-{uuid.uuid4().hex[:8]}", password=None, role=User.Roles.ADMIN
    )


def _deployment(name):
    return Deployment.objects.create(name=f"{name}-{uuid.uuid4().hex[:8]}", owner=_person(f"owner-{name}"))


def _client(user=None):
    client = APIClient()
    client.force_authenticate(user=user or _person("admin"))
    return client


def _supersede_by_drift(dep):
    """A re-derive that closes the claim's current version and opens a new one."""
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="late", identifier="late",
        classification=Asset.Classification.APPROVED, metadata={"tools": []},
    )
    return derive_claims(dep)


def _versions(dep):
    return list(
        AssuranceClaim.objects.filter(deployment=dep, claim_type=ClaimType.EFFECTIVE_ACCESS).order_by("pk")
    )


def _post(client, claim_uuid, to_status, box):
    try:
        response = client.post(
            f"/api/assurance/claims/{claim_uuid}/transition/", {"to_status": to_status, "note": "race"},
            format="json",
        )
        box["code"] = response.status_code
        box["body"] = response.json() if response.status_code < 500 else response.content[:300]
    except Exception as exc:  # noqa: BLE001 -- a thread's failure is the finding, reported by the test
        box["exc"] = repr(exc)
    finally:
        connection.close()


class _Window:
    """The transition route's read of the claim, observed -- and, when ``wait``,
    held open until released -- in the request thread named SLOW. The real
    ``get_object`` runs unchanged; this only signals after it returns."""

    def __init__(self, monkeypatch, *, wait: bool):
        self.loaded = threading.Event()
        self.go = threading.Event()
        original = assurance_views.ClaimViewSet.get_object
        window = self

        def observed(view):
            obj = original(view)
            if threading.current_thread().name == "SLOW":
                window.loaded.set()
                if wait:
                    window.go.wait(20)
            return obj

        monkeypatch.setattr(assurance_views.ClaimViewSet, "get_object", observed)

    def start(self, client, claim_uuid, to_status):
        box: dict = {}
        thread = threading.Thread(target=_post, args=(client, claim_uuid, to_status, box), name="SLOW")
        thread.start()
        assert self.loaded.wait(20), "the request never read the claim"
        return thread, box

    def finish(self, thread):
        self.go.set()
        thread.join(30)
        assert not thread.is_alive()


# ---------------------------------------------------------------------------
# Widened windows (r_stop_races.py R1-R3)
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_a_contradiction_read_before_a_re_derive_superseded_its_version_lands_on_the_current_version(monkeypatch):
    """R1. The contradiction read version A; a re-derive closed A and opened B; the
    contradiction then landed on A (200) and B -- the claim everything reads --
    stayed VERIFIED."""
    dep = _deployment("r1")
    addressed = _access_claim(dep)
    assert addressed.status == Status.VERIFIED
    window = _Window(monkeypatch, wait=True)
    thread, box = window.start(_client(), addressed.uuid, "contradicted")
    _supersede_by_drift(dep)
    window.finish(thread)

    assert box.get("code") == 200, box
    current = _current(dep)
    assert current.pk != addressed.pk
    assert current.status == Status.CONTRADICTED
    addressed.refresh_from_db()
    assert addressed.status == Status.SUPERSEDED and addressed.valid_to is not None
    stop = current.events.exclude(actor=None).order_by("-pk").first()
    assert stop.to_status == Status.CONTRADICTED
    assert f"addressed to superseded {addressed.uuid}" in stop.note
    assert box["body"]["status"] == Status.CONTRADICTED


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("stop", [Status.REVOKED, Status.CONTRADICTED])
@pytest.mark.parametrize("move", [Status.PARTIALLY_VERIFIED, Status.SUPPORTED])
def test_a_move_read_before_a_stop_committed_is_refused_and_the_stop_stands(monkeypatch, stop, move):
    """R2/R3. A person's move read the claim VERIFIED; a stop committed; the move
    then landed over the stop (both 200) and the claim read the person's pass."""
    dep = _deployment(f"r2-{stop}-{move}")
    claim = _access_claim(dep)
    window = _Window(monkeypatch, wait=True)
    thread, box = window.start(_client(), claim.uuid, move)
    stopped = _client().post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": stop, "note": "stop"}, format="json"
    )
    assert stopped.status_code == 200, stopped.content
    window.finish(thread)

    assert box.get("code") == 409, box
    assert "re-read" in box["body"]["detail"]
    claim.refresh_from_db()
    assert claim.status == stop
    # The person's move was never recorded over the stop.
    assert not claim.events.filter(to_status=move).exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    "first, second, final",
    [
        (Status.REVOKED, Status.CONTRADICTED, Status.REVOKED),
        (Status.CONTRADICTED, Status.REVOKED, Status.REVOKED),
    ],
)
def test_a_stop_read_before_another_stop_committed_still_lands_and_a_withdrawal_stays_terminal(
    monkeypatch, first, second, final
):
    """A stop never loses a race: read before another stop committed, it is applied
    to the row as committed -- recorded (200), never a 409 or a 400 -- and a
    withdrawal is never undone by a contradiction that read the claim earlier."""
    dep = _deployment(f"ss-{first}-{second}")
    claim = _access_claim(dep)
    window = _Window(monkeypatch, wait=True)
    thread, box = window.start(_client(), claim.uuid, second)
    committed = _client().post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": first, "note": "first"}, format="json"
    )
    assert committed.status_code == 200, committed.content
    window.finish(thread)

    assert box.get("code") == 200, box
    claim.refresh_from_db()
    assert claim.status == final
    assert claim.events.exclude(actor=None).order_by("-pk").first().to_status in (second, final)


# ---------------------------------------------------------------------------
# Natural arrivals (r_stop_races_natural.py N1, N2): nothing waits but the lock
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_a_move_arriving_while_a_revoke_commits_is_refused_and_the_revoke_stands(monkeypatch):
    """N2. The move read the claim while the revoke's transaction was open (WAL lets
    the read through), waited on the write lock, and wrote its decision from the
    row it had read: both 200, the claim ``partially_verified``, un-revoked."""
    dep = _deployment("n2")
    claim = _access_claim(dep)
    window = _Window(monkeypatch, wait=False)
    client = _client()
    with transaction.atomic():
        apply_claim_transition(AssuranceClaim.objects.get(pk=claim.pk), Status.REVOKED, actor=_person(), note="stop")
        thread, box = window.start(client, claim.uuid, Status.PARTIALLY_VERIFIED)
        time.sleep(0.3)  # the move has read the claim; it is waiting on the lock or about to
    thread.join(30)

    assert box.get("code") == 409, box
    claim.refresh_from_db()
    assert claim.status == Status.REVOKED
    assert not claim.events.filter(to_status=Status.PARTIALLY_VERIFIED).exists()


@pytest.mark.django_db(transaction=True)
def test_a_contradiction_arriving_while_a_re_derive_commits_lands_on_the_new_version(monkeypatch):
    """N1. The contradiction read version A while the superseding re-derive was in
    its transaction, and was then refused 400 naming B: the current version stayed
    VERIFIED."""
    dep = _deployment("n1")
    addressed = _access_claim(dep)
    window = _Window(monkeypatch, wait=False)
    client = _client()
    with transaction.atomic():
        _supersede_by_drift(dep)
        thread, box = window.start(client, addressed.uuid, Status.CONTRADICTED)
        time.sleep(0.3)
    thread.join(30)

    assert box.get("code") == 200, box
    current = _current(dep)
    assert current.pk != addressed.pk and current.status == Status.CONTRADICTED


# ---------------------------------------------------------------------------
# The same rules, without threads
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("stop", [Status.CONTRADICTED, Status.REVOKED])
def test_a_stop_addressed_to_a_superseded_version_stops_the_claims_current_version(stop):
    """Owner decision (round 3): a stop addressed to a superseded version is applied
    to the claim identity's current version -- it only lowers assurance -- and the
    event says which version it was addressed to. It was a 400 that left the
    current version un-stopped."""
    dep = _deployment(f"sup-{stop}")
    old = _access_claim(dep)
    _supersede_by_drift(dep)
    current = _current(dep)
    assert current.pk != old.pk and current.status == Status.VERIFIED

    response = _client().post(
        f"/api/assurance/claims/{old.uuid}/transition/", {"to_status": stop, "note": "take it down"}, format="json"
    )

    assert response.status_code == 200, response.content
    assert response.json()["status"] == stop
    current.refresh_from_db()
    old.refresh_from_db()
    assert current.status == stop
    assert old.status == Status.SUPERSEDED
    event = current.events.exclude(actor=None).order_by("-pk").first()
    assert event.to_status == stop
    assert f"addressed to superseded {old.uuid}" in event.note
    assert "take it down" in event.note


@pytest.mark.django_db
def test_a_stop_addressed_to_a_superseded_version_of_a_withdrawn_claim_is_recorded_and_it_stays_withdrawn():
    dep = _deployment("sup-rev")
    old = _access_claim(dep)
    _supersede_by_drift(dep)
    current = _current(dep)
    apply_claim_transition(current, Status.REVOKED, actor=_person(), note="withdrawn")

    response = _client().post(
        f"/api/assurance/claims/{old.uuid}/transition/", {"to_status": "contradicted"}, format="json"
    )

    assert response.status_code == 200, response.content
    current.refresh_from_db()
    assert current.status == Status.REVOKED
    last = current.events.order_by("-pk").first()
    assert last.actor is not None and f"addressed to superseded {old.uuid}" in last.note


@pytest.mark.django_db
def test_a_move_decided_from_a_row_read_before_a_stop_is_refused_and_a_stop_is_applied_to_the_committed_row():
    """The rule itself, one connection: whatever the caller's copy of the claim
    says, the transition decides from the row as committed when it writes."""
    dep = _deployment("cas")
    read_early = _access_claim(dep)                       # VERIFIED, as the caller read it
    apply_claim_transition(AssuranceClaim.objects.get(pk=read_early.pk), Status.REVOKED, actor=_person(), note="stop")

    with pytest.raises(IllegalClaimTransition, match="re-read") as refused:
        apply_claim_transition(read_early, Status.SUPPORTED, actor=_person(), note="late")
    assert isinstance(refused.value, claims_module.ClaimChanged)
    assert AssuranceClaim.objects.get(pk=read_early.pk).status == Status.REVOKED

    # A stop from the same stale copy lands on the committed row: withdrawn stays withdrawn.
    event = apply_claim_transition(read_early, Status.CONTRADICTED, actor=_person(), note="late stop")
    assert event.claim_id == read_early.pk
    assert AssuranceClaim.objects.get(pk=read_early.pk).status == Status.REVOKED
    assert event.cause == ClaimEvent.CAUSE_PERSON_READING


@pytest.mark.django_db
def test_a_move_decided_from_a_row_read_before_a_supersession_is_refused():
    dep = _deployment("cas-sup")
    read_early = _access_claim(dep)
    _supersede_by_drift(dep)

    with pytest.raises(IllegalClaimTransition, match="re-read") as refused:
        apply_claim_transition(read_early, Status.SUPPORTED, actor=_person(), note="late")
    assert isinstance(refused.value, claims_module.ClaimChanged)
    assert _current(dep).status == Status.VERIFIED
    read_early.refresh_from_db()
    assert read_early.status == Status.SUPERSEDED


@pytest.mark.django_db
def test_a_move_whose_read_is_still_the_committed_row_is_unaffected():
    dep = _deployment("cas-ok")
    claim = _access_claim(dep)
    response = _client().post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "supported"}, format="json"
    )
    assert response.status_code == 200, response.content
    claim.refresh_from_db()
    assert claim.status == Status.SUPPORTED
