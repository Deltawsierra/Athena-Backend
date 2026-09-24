"""A demonstrated chain outcome is one an engine signed, and nothing else.

Every chain status claims an exercise, and ``basis: demonstrated`` is the field
that says a run happened. Until now an operator POST could set it: fifty typed-in
``held`` rows marked demonstrated composed to READY with nothing exercised. The
engines now sign what they observe (Achilles per dispatch, Athena per scan), and
this suite holds the other half: the only way a demonstrated row reaches the
record is a verified envelope, checked for what a signature does NOT prove --
where it was meant for, whether it was already recorded, and when.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import composition as comp
from assurance import observed_outcomes
from assurance.models import ApprovedWorkflow, Deployment, WorkflowChainOutcome
from assurance.workflow_chains import composition_for

pytestmark = pytest.mark.django_db

User = get_user_model()
ACHILLES = Ed25519PrivateKey.generate()
ATHENA = Ed25519PrivateKey.generate()
STRANGER = Ed25519PrivateKey.generate()


def _now():
    return datetime.now(dt_timezone.utc)


@pytest.fixture(autouse=True)
def keyring(tmp_path, monkeypatch):
    path = tmp_path / "keyring.json"
    path.write_text(
        json.dumps(
            [
                {"engine": "achilles", "public_key": base64.b64encode(oc.raw_public_key(ACHILLES)).decode()},
                {"engine": "athena", "public_key": base64.b64encode(oc.raw_public_key(ATHENA)).decode()},
            ]
        )
    )
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(path))
    return path


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _deployment():
    return Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())


def _client():
    c = APIClient()
    c.force_authenticate(user=_admin())
    return c


def _url(dep):
    return f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/observed/"


def _signed(dep, *, workflow="refund-over-limit", status=oc.HELD, key=ACHILLES, engine="achilles",
            observed_at=None, reason="", deployment=None, outcome_id=None):
    outcome = oc.build_outcome(
        deployment=deployment or str(dep.uuid),
        workflow=workflow,
        status=status,
        engine=engine,
        engine_version="1.0.0",
        run_id="run-1",
        evidence_digest="sha256:" + "ab" * 32,
        observed_at=observed_at or (_now() - timedelta(minutes=1)),
        reason=reason or ("" if status == oc.HELD else "the gate refused the dispatch"),
        outcome_id=outcome_id,
    )
    return oc.sign_outcome(outcome, key)


# ----------------------------------------------------------- the route


def test_a_signed_outcome_is_recorded_as_demonstrated_with_its_evidence():
    dep = _deployment()
    envelope = _signed(dep)

    response = _client().post(_url(dep), envelope, format="json")

    assert response.status_code == 201, response.content
    row = WorkflowChainOutcome.objects.get(deployment=dep)
    assert row.basis == comp.BASIS_DEMONSTRATED
    assert row.status == comp.HELD
    assert row.observer_engine == "achilles"
    assert row.observer_key_id == oc.key_id_for(oc.raw_public_key(ACHILLES))
    assert row.evidence_digest == "sha256:" + "ab" * 32
    assert row.envelope == envelope
    assert row.rests_on_signed_evidence
    assert response.json()["outcomes"][0]["signed"] is True


def test_a_batch_is_recorded_whole_or_not_at_all():
    dep = _deployment()
    good = _signed(dep)
    forged = dict(_signed(dep, workflow="payout"))
    forged["signatures"] = [{**forged["signatures"][0], "sig": base64.b64encode(b"\0" * 64).decode()}]

    response = _client().post(_url(dep), {"envelopes": [good, forged]}, format="json")

    assert response.status_code == 400
    assert [r["index"] for r in response.json()["refused"]] == [1]
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()


@pytest.mark.parametrize(
    ("make", "why"),
    [
        (lambda dep: _signed(dep, key=STRANGER), "unknown_key"),
        (lambda dep: _signed(dep, key=ACHILLES, engine="athena"), "wrong_observer"),
        (lambda dep: _signed(dep, deployment=str(uuid.uuid4())), "not this one"),
        (lambda dep: _signed(dep, observed_at=_now() + timedelta(hours=1)), "in the future"),
        (lambda dep: _signed(dep, observed_at=_now() - timedelta(days=45)), "window"),
        (lambda dep: {"payloadType": oc.OUTCOME_PAYLOAD_TYPE}, "malformed"),
    ],
    ids=["untrusted-key", "key-for-another-engine", "another-deployment", "future", "too-old", "malformed"],
)
def test_what_a_signature_does_not_prove_is_checked(make, why):
    dep = _deployment()
    response = _client().post(_url(dep), make(dep), format="json")
    assert response.status_code == 400, response.content
    assert why in response.json()["refused"][0]["reason"]
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()


def test_an_outcome_is_recorded_once_anywhere():
    dep, other = _deployment(), _deployment()
    envelope = _signed(dep)
    client = _client()
    assert client.post(_url(dep), envelope, format="json").status_code == 201

    again = client.post(_url(dep), envelope, format="json")
    assert again.status_code == 400
    assert "already recorded" in again.json()["refused"][0]["reason"]

    twice = client.post(_url(dep), {"envelopes": [_signed(dep, outcome_id=uuid.uuid4().hex)] * 2}, format="json")
    assert twice.status_code == 400
    assert "twice" in twice.json()["refused"][0]["reason"] or "twice" in twice.json()["refused"][-1]["reason"]
    assert WorkflowChainOutcome.objects.filter(deployment=dep).count() == 1
    assert not WorkflowChainOutcome.objects.filter(deployment=other).exists()


def test_a_stale_verdict_cannot_be_replayed_behind_a_newer_one():
    """A held from yesterday, posted after a violated from today, is a replay of a
    stale verdict. The rule already ranks by recency; this refuses it at the door."""
    dep = _deployment()
    client = _client()
    newer = _signed(dep, status=oc.NOT_DEMONSTRATED, observed_at=_now() - timedelta(minutes=5))
    older = _signed(dep, status=oc.HELD, observed_at=_now() - timedelta(hours=5))
    assert client.post(_url(dep), newer, format="json").status_code == 201

    response = client.post(_url(dep), older, format="json")

    assert response.status_code == 400
    assert "older than the newest" in response.json()["refused"][0]["reason"]
    # A different engine's older outcome is not a replay of this one's.
    assert client.post(
        _url(dep), _signed(dep, key=ATHENA, engine="athena", observed_at=_now() - timedelta(hours=5)),
        format="json",
    ).status_code == 201


def test_no_keyring_means_nothing_can_be_verified_and_it_says_so(monkeypatch):
    monkeypatch.delenv(observed_outcomes.KEYRING_ENV)
    dep = _deployment()
    response = _client().post(_url(dep), _signed(dep), format="json")
    assert response.status_code == 503
    assert observed_outcomes.KEYRING_ENV in response.json()["error"]


def test_a_keyring_holding_a_key_that_verifies_everything_is_refused(tmp_path, monkeypatch):
    """The small-order key that forged a held outcome against the first verifier.
    A keyring holding it is a configuration error, not a trust anchor."""
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"engine": "achilles", "public_key": base64.b64encode(bytes(32)).decode()}]))
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(path))
    with pytest.raises(observed_outcomes.KeyringUnavailable):
        observed_outcomes.load_keyring()


def test_one_key_cannot_be_bound_to_two_engines(tmp_path):
    raw = base64.b64encode(oc.raw_public_key(ACHILLES)).decode()
    path = tmp_path / "twice.json"
    path.write_text(json.dumps([{"engine": "achilles", "public_key": raw}, {"engine": "athena", "public_key": raw}]))
    with pytest.raises(observed_outcomes.KeyringUnavailable):
        observed_outcomes.load_keyring(str(path))


def test_only_admins_may_post_observed_outcomes():
    dep = _deployment()
    analyst = User.objects.create_user(username="analyst", password="x", role=User.Roles.ANALYST)
    c = APIClient()
    c.force_authenticate(user=analyst)
    assert c.post(_url(dep), _signed(dep), format="json").status_code == 403


def test_an_oversized_body_is_refused_before_anything_is_verified():
    dep = _deployment()
    padding = "x" * (observed_outcomes.MAX_BODY_BYTES + 1)
    response = _client().post(_url(dep), {"envelopes": [], "padding": padding}, format="json")
    assert response.status_code == 413


# ----------------------------------------------------------- the operator route


def test_an_operator_cannot_type_demonstrated():
    dep = _deployment()
    response = _client().post(
        f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/",
        {"workflow": "refund-over-limit", "status": comp.HELD, "basis": comp.BASIS_DEMONSTRATED},
        format="json",
    )
    assert response.status_code == 400
    assert "signed outcome" in json.dumps(response.json())
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()


def test_a_typed_in_held_cannot_make_a_workflow_exercised_and_a_signed_one_can():
    """The case #239 exists for. The same held, twice: typed in, it leaves the
    workflow unexercised; signed by the engine that observed it, it does not."""
    dep = _deployment()
    ApprovedWorkflow.objects.create(deployment=dep, slug="refund-over-limit", name="Refund")
    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="refund-over-limit", status=comp.HELD,
        basis=comp.BASIS_DEMONSTRATED, observed_at=_now() - timedelta(hours=1),
    )
    typed = composition_for(dep)
    assert typed.workflows_unexercised == 1
    assert "refund-over-limit" in typed.unexercised

    assert _client().post(_url(dep), _signed(dep), format="json").status_code == 201
    signed = composition_for(dep)
    assert signed.workflows_unexercised == 0
