"""A supersession of a legal obligation over many deployments never holds back a stop
(the SAFETY RULE; the lead's decision of 19 Oct on #173).

A supersession binds every deployment the previous version bound. It used to flag each
one's claims and refresh each one's decision inside its own transaction -- under the
database-wide write lock every transaction takes here (``BEGIN IMMEDIATE``) -- so a
stop made meanwhile waited for all of them: measured over two hundred deployments of
three claims each, a pause, a revoke and a failsafe draft each took two to five
seconds against a bound of a quarter of one. Now its own transaction records the
version and owes each deployment its review, a fixed number of statements, and the
flags are written once it commits, one deployment per short transaction
(:func:`assurance.legal.settle_reviews_owed`).

This MEASURES it, as the stop suite's latency test does: every stop's request is
prepared first, the supersession is started over the fan-out, and once it is flagging
claims each stop is made and timed. It asserts that each stop answered within the
stop suite's bound while the supersession was still at work -- not the structure that
should make it so.
"""

from __future__ import annotations

import threading
import time
import uuid

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.db.models.signals import post_save
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.decision import recompute_decision
from assurance.models import AssuranceClaim, ClaimEvent, Deployment, LegalObligation, LegalStatus
from tests.test_no_control_holds_back_a_stop import STOP_LATENCY_BOUND, _admin, _claim, _deployment
from tests.test_no_control_holds_back_a_stop import configure, rates  # noqa: F401 - fixtures, used by name

User = get_user_model()

#: How many deployments the obligation binds, and how many current claims each has.
FAN_OUT = 200
CLAIMS_EACH = 3
#: How many times every stop is made during the one supersession. A stop kept out by
#: a loop that retakes the lock at once is kept out only when its retries keep landing
#: inside that loop's transactions, so one try of each can be lucky; three of each,
#: back to back for as long as the supersession runs, are not.
ROUNDS = 3


def _fan_out():
    """FAN_OUT deployments, each with CLAIMS_EACH current claims and a stored decision,
    all bound to one obligation."""
    owner = _admin()
    deployments = Deployment.objects.bulk_create(
        [Deployment(name=f"bound-{i}-{uuid.uuid4().hex[:6]}", owner=owner) for i in range(FAN_OUT)]
    )
    now = timezone.now()
    AssuranceClaim.objects.bulk_create(
        [
            AssuranceClaim(
                deployment=d, claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY, statement="s",
                fingerprint=f"fp-{j}", system_fingerprint="s", policy_version="p", environment=d.environment,
                status=AssuranceClaim.ClaimStatus.VERIFIED, valid_from=now, effective_from=now,
            )
            for d in deployments
            for j in range(CLAIMS_EACH)
        ]
    )
    obligation = LegalObligation.objects.create(
        jurisdiction="EU", authority_tier="regulation", source="GDPR", source_version="2016/679",
        operative_date=now.date(),
    )
    obligation.deployments.add(*deployments)
    for d in deployments:
        recompute_decision(Deployment.objects.get(pk=d.pk))
    return deployments, obligation


def _prepared_stops(operator):
    """Each stop's request, with everything it acts on made first: (name, make)."""
    from pentest.models import PentestScan

    to_pause, to_revoke, to_contradict, to_switch_off = (_deployment() for _ in range(4))
    revoke, contradict = _claim(to_revoke), _claim(to_contradict)
    lost = PentestScan.objects.create(
        user=operator, target_url="https://client.example/", consent=True, status=PentestScan.STATUS_UNKNOWN
    )
    leaver = _admin()
    engine_id = f"athena-{uuid.uuid4().hex[:8]}"
    client = APIClient()
    client.force_authenticate(user=operator)
    base = "/api/assurance"
    return [
        ("pause", 200, lambda: client.post(f"{base}/deployments/{to_pause.uuid}/recompute/", {"paused": True},
                                           format="json")),
        ("revoke", 200, lambda: client.post(f"{base}/claims/{revoke.uuid}/transition/", {"to_status": "revoked"},
                                            format="json")),
        ("contradict", 200, lambda: client.post(f"{base}/claims/{contradict.uuid}/transition/",
                                                {"to_status": "contradicted"}, format="json")),
        ("failsafe draft", 201, lambda: client.post("/api/failsafe/commands/",
                                                    {"action": "stand_down", "engine_id": engine_id}, format="json")),
        ("dispatch off", 200, lambda: client.put(f"{base}/deployments/{to_switch_off.uuid}/dispatch-policy/",
                                                 {"enabled": False}, format="json")),
        ("scan stop", 202, lambda: client.post(f"/api/pentest/scans/{lost.uuid}/stop/", {}, format="json")),
        ("operator removed", 204, lambda: client.delete(f"/api/accounts/users/{leaver.pk}/")),
    ]


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
def test_every_stop_answers_within_its_bound_while_a_supersession_over_many_deployments_runs():
    deployments, v1 = _fan_out()
    stops = [stop for _round in range(ROUNDS) for stop in _prepared_stops(_admin())]
    admin = _admin()
    flagging, finished = threading.Event(), threading.Event()
    run: dict = {}

    def flagged(sender, instance, created=False, **kwargs):
        if created and threading.current_thread() is run.get("thread"):
            flagging.set()

    def supersede():
        client = APIClient()
        client.force_authenticate(user=admin)
        try:
            began = time.monotonic()
            response = client.post(
                f"/api/assurance/deployments/{deployments[0].uuid}/legal-obligations/{v1.uuid}/supersede/",
                {"source_version": "2016/679 as amended", "operative_date": "2027-01-01"}, format="json",
            )
            run["status"], run["took"] = response.status_code, time.monotonic() - began
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            run["error"] = exc
        finally:
            finished.set()
            flagging.set()
            connection.close()

    post_save.connect(flagged, sender=ClaimEvent, weak=False, dispatch_uid="supersede-fan-out-flagging")
    try:
        run["thread"] = threading.Thread(target=supersede)
        run["thread"].start()
        assert flagging.wait(timeout=120), "the supersession never began flagging"
        assert not finished.is_set(), f"the supersession ended before it flagged anything: {run}"
        timings = []
        for name, served, make in stops:
            during = not finished.is_set()
            began = time.monotonic()
            response = make()
            timings.append((name, round(time.monotonic() - began, 3), response.status_code, served, during))
        run["thread"].join(timeout=600)
    finally:
        post_save.disconnect(sender=ClaimEvent, dispatch_uid="supersede-fan-out-flagging")

    assert "error" not in run and run.get("status") == 201, run
    assert [(name, code) for name, _took, code, _served, _during in timings] == [
        (name, served) for name, _took, _code, served, _during in timings
    ], timings
    # Made while the supersession was still at work, or this proved nothing.
    assert all(during for *_rest, during in timings), (timings, run)
    slow = [(name, took) for name, took, *_rest in timings if took > STOP_LATENCY_BOUND]
    assert slow == [], (
        f"stops made during a supersession over {FAN_OUT} deployments took longer than "
        f"{STOP_LATENCY_BOUND}s: {slow} (the supersession took {run.get('took', 0):.1f}s)"
    )
    # And the supersession it did not wait on was whole: every claim flagged, nothing owed.
    from assurance.models import LegalReviewOwed

    assert not LegalReviewOwed.objects.exists()
    flagged_claims = AssuranceClaim.objects.filter(deployment__in=deployments, legal_status=LegalStatus.REVIEW_PENDING)
    assert flagged_claims.count() == FAN_OUT * CLAIMS_EACH
