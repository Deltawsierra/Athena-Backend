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
from assurance.workflow_chains import composition_for, composition_signal

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


def test_a_refusal_found_against_the_record_still_refuses_the_whole_batch_and_names_its_envelope():
    """The checks against what is already recorded run after the envelope checks
    pass. A refusal there must still record nothing, and must name the envelope by
    its place in the batch the caller sent."""
    dep = _deployment()
    client = _client()
    recorded = _signed(dep, workflow="refund-over-limit")
    assert client.post(_url(dep), recorded, format="json").status_code == 201

    batch = [_signed(dep, workflow="payout"), _signed(dep, workflow="export"), recorded]
    response = client.post(_url(dep), {"envelopes": batch}, format="json")

    assert response.status_code == 400, response.content
    refused = response.json()["refused"]
    assert [r["index"] for r in refused] == [2]
    assert "already recorded" in refused[0]["reason"]
    assert set(WorkflowChainOutcome.objects.filter(deployment=dep).values_list("workflow", flat=True)) == {
        "refund-over-limit"
    }


@pytest.mark.parametrize("order", ["newer-first", "older-first"])
def test_a_stale_verdict_is_refused_whether_it_arrives_with_the_newer_one_or_after_it(order):
    dep = _deployment()
    newer = _signed(dep, status=oc.NOT_DEMONSTRATED, observed_at=_now() - timedelta(minutes=5))
    older = _signed(dep, status=oc.HELD, observed_at=_now() - timedelta(hours=5))
    batch = [newer, older] if order == "newer-first" else [older, newer]

    response = _client().post(_url(dep), {"envelopes": batch}, format="json")

    assert response.status_code == 400, response.content
    refused = response.json()["refused"]
    assert [r["index"] for r in refused] == [batch.index(older)]
    assert "in this same batch" in refused[0]["reason"]
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()
    # The same engine on another workflow, or another engine on this one, is no replay.
    alongside = [
        newer,
        _signed(dep, workflow="payout", observed_at=_now() - timedelta(hours=5)),
        _signed(dep, key=ATHENA, engine="athena", observed_at=_now() - timedelta(hours=5)),
    ]
    assert _client().post(_url(dep), {"envelopes": alongside}, format="json").status_code == 201


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
    # And it is not READY: the approved workflow counts as never having reported.
    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE

    assert _client().post(_url(dep), _signed(dep), format="json").status_code == 201
    signed = composition_for(dep)
    assert signed.workflows_unexercised == 0
    assert composition_signal(dep) == comp.READY


# ------------------------------------------------ what a recorded row rests on


def _operator_url(dep):
    return f"/api/assurance/deployments/{dep.uuid}/chain-outcomes/"


def _ingested(dep, **kw):
    assert _client().post(_url(dep), _signed(dep, **kw), format="json").status_code == 201
    return WorkflowChainOutcome.objects.filter(deployment=dep).order_by("-created_at").first()


def _approved(dep, *slugs):
    for slug in slugs:
        ApprovedWorkflow.objects.create(deployment=dep, slug=slug, name=slug)


def test_a_row_is_demonstrated_only_while_its_envelope_verifies_and_says_what_the_row_says():
    """Presence of the evidence columns proved nothing: an ORM row with
    ``envelope={}`` read as a run, and so did a genuine envelope copied from
    another deployment. Every column the rule reads must be one the signature
    covers, checked on every read."""
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    row = _ingested(dep)
    assert row.rests_on_signed_evidence
    assert composition_signal(dep) == comp.READY

    tampered = {
        "an empty envelope": {"envelope": {}},
        "another outcome_id": {"outcome_id": uuid.uuid4().hex},
        "another workflow": {"workflow": "payout"},
        "another status": {"status": comp.VIOLATED},
        "another instant": {"observed_at": row.observed_at - timedelta(seconds=1)},
        "another engine": {"observer_engine": "athena"},
        "another key id": {"observer_key_id": "k" * 16},
        "another digest": {"evidence_digest": "sha256:" + "00" * 32},
    }
    for why, change in tampered.items():
        WorkflowChainOutcome.objects.filter(pk=row.pk).update(**change)
        reread = WorkflowChainOutcome.objects.get(pk=row.pk)
        assert not reread.rests_on_signed_evidence, why
        assert composition_for(dep).basis_census[comp.BASIS_ATTESTED] == 1, why
        # Restore, so each change is tested alone.
        WorkflowChainOutcome.objects.filter(pk=row.pk).update(
            envelope=row.envelope, outcome_id=row.outcome_id, workflow=row.workflow,
            status=row.status, observed_at=row.observed_at, observer_engine=row.observer_engine,
            observer_key_id=row.observer_key_id, evidence_digest=row.evidence_digest,
        )
    assert WorkflowChainOutcome.objects.get(pk=row.pk).rests_on_signed_evidence


def test_a_genuine_envelope_copied_onto_another_deployment_is_not_evidence_there():
    source, target = _deployment(), _deployment()
    _approved(target, "refund-over-limit")
    genuine = _ingested(source)
    WorkflowChainOutcome.objects.create(
        deployment=target, workflow=genuine.workflow, status=genuine.status,
        basis=comp.BASIS_DEMONSTRATED, observed_at=genuine.observed_at,
        outcome_id=uuid.uuid4().hex, observer_engine=genuine.observer_engine,
        observer_key_id=genuine.observer_key_id, evidence_digest=genuine.evidence_digest,
        envelope=genuine.envelope,
    )
    copied = WorkflowChainOutcome.objects.get(deployment=target)
    assert not copied.rests_on_signed_evidence
    assert composition_signal(target) == comp.NEEDS_MORE_EVIDENCE


def test_withdrawing_a_key_withdraws_what_it_vouched_for(tmp_path, monkeypatch):
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert composition_signal(dep) == comp.READY

    only_athena = tmp_path / "rotated.json"
    only_athena.write_text(json.dumps(
        [{"engine": "athena", "public_key": base64.b64encode(oc.raw_public_key(ATHENA)).decode()}]
    ))
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(only_athena))
    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE
    assert composition_for(dep).basis_census[comp.BASIS_ATTESTED] == 1

    monkeypatch.delenv(observed_outcomes.KEYRING_ENV)
    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE, "no keyring: nothing can be shown signed"


def test_the_basis_census_reports_a_typed_in_demonstrated_as_attested():
    """``_basis_of`` reads a demonstrated row with no evidence as ATTESTED -- a
    person asserted it -- not as unknown. The census is where that shows."""
    dep = _deployment()
    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="w", status=comp.HELD, basis=comp.BASIS_DEMONSTRATED,
        observed_at=_now() - timedelta(hours=1),
    )
    census = composition_for(dep).basis_census
    assert census[comp.BASIS_ATTESTED] == 1
    assert census[comp.BASIS_UNKNOWN] == 0
    assert census[comp.BASIS_DEMONSTRATED] == 0


# ------------------------------------------------ an assertion cannot outrank evidence


def test_a_future_dated_typed_in_held_is_refused_and_could_not_hide_a_signed_violation():
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep, status=oc.VIOLATED)
    assert composition_signal(dep) == comp.NOT_RECOMMENDED

    far = _client().post(
        _operator_url(dep),
        {"workflow": "refund-over-limit", "status": comp.HELD, "basis": comp.BASIS_ATTESTED,
         "observed_at": "2099-01-01T00:00:00Z"},
        format="json",
    )
    assert far.status_code == 400
    assert "in the future" in json.dumps(far.json())

    # Within the skew allowance it is accepted -- and still does not displace the
    # signed violation, however much later it is dated.
    near = _client().post(
        _operator_url(dep),
        {"workflow": "refund-over-limit", "status": comp.HELD, "basis": comp.BASIS_ATTESTED,
         "observed_at": (_now() + timedelta(minutes=1)).isoformat()},
        format="json",
    )
    assert near.status_code == 200, near.content
    composed = composition_for(dep)
    assert composed.census[comp.VIOLATED] == 1
    assert composition_signal(dep) == comp.NOT_RECOMMENDED


def test_evidence_fields_posted_to_the_operator_route_are_ignored():
    dep = _deployment()
    response = _client().post(
        _operator_url(dep),
        {"workflow": "w", "status": comp.HELD, "basis": comp.BASIS_ATTESTED,
         "outcome_id": uuid.uuid4().hex, "observer_engine": "achilles",
         "observer_key_id": "k", "evidence_digest": "sha256:" + "ab" * 32},
        format="json",
    )
    assert response.status_code == 200, response.content
    row = WorkflowChainOutcome.objects.get(deployment=dep)
    assert row.outcome_id is None
    assert (row.observer_engine, row.observer_key_id, row.evidence_digest) == ("", "", "")
    assert not row.rests_on_signed_evidence


# ------------------------------------------------ the replay rule's edges


def test_the_replay_rule_is_per_deployment_per_workflow_and_admits_the_same_instant():
    dep, other = _deployment(), _deployment()
    at = _now() - timedelta(minutes=5)
    _ingested(dep, workflow="refund-over-limit", observed_at=at)

    # Another deployment's newer outcome is not this one's history.
    _ingested(other, workflow="refund-over-limit", observed_at=_now() - timedelta(minutes=1))
    # Nor is another workflow's.
    _ingested(dep, workflow="payout", observed_at=_now() - timedelta(minutes=1))
    assert _client().post(
        _url(dep), _signed(dep, workflow="refund-over-limit", observed_at=at - timedelta(minutes=1)),
        format="json",
    ).status_code == 400, "older than this engine's newest for this workflow here"
    # A second, distinct outcome at the same instant is not older than the newest.
    same = _client().post(
        _url(dep), _signed(dep, workflow="refund-over-limit", observed_at=at, status=oc.VIOLATED),
        format="json",
    )
    assert same.status_code == 201, same.content
    assert composition_for(dep).census[comp.VIOLATED] == 1


def test_one_more_than_the_batch_limit_is_refused():
    dep = _deployment()
    envelopes = [_signed(dep, workflow=f"w{n}") for n in range(observed_outcomes.BATCH_LIMIT + 1)]
    response = _client().post(_url(dep), {"envelopes": envelopes}, format="json")
    assert response.status_code == 400
    assert str(observed_outcomes.BATCH_LIMIT) in json.dumps(response.json())
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()
    exact = _client().post(_url(dep), {"envelopes": envelopes[:-1]}, format="json")
    assert exact.status_code == 201, exact.content


# ------------------------------------------------ refusals, not server errors


@pytest.mark.parametrize("content", ["[]", "{}", "[" * 100_000], ids=["empty-list", "object", "nested"])
def test_an_unusable_keyring_is_a_503_with_a_reason(tmp_path, monkeypatch, content):
    path = tmp_path / "unusable.json"
    path.write_text(content)
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(path))
    dep = _deployment()
    response = _client().post(_url(dep), _signed(dep), format="json")
    assert response.status_code == 503, response.content
    assert "keyring" in response.json()["error"]


def test_a_multipart_body_is_refused_not_a_server_error():
    dep = _deployment()
    response = _client().post(_url(dep), {"envelopes": "x"}, format="multipart")
    assert response.status_code == 415, response.content
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()


def test_a_body_past_djangos_own_cap_still_gets_this_routes_413():
    from django.conf import settings

    dep = _deployment()
    too_big = (settings.DATA_UPLOAD_MAX_MEMORY_SIZE or 2_621_440) + 1024
    body = json.dumps({"envelopes": [], "padding": "x" * too_big})
    response = _client().post(_url(dep), body, content_type="application/json")
    assert response.status_code == 413, response.status_code

    exact = json.dumps({"p": "x" * (observed_outcomes.MAX_BODY_BYTES - len(json.dumps({"p": ""})))})
    assert len(exact) == observed_outcomes.MAX_BODY_BYTES
    assert _client().post(_url(dep), exact, content_type="application/json").status_code != 413


# ------------------------------------------------ the migration


def _migration_0032():
    import importlib

    return importlib.import_module("assurance.migrations.0032_signed_chain_outcomes")


def test_the_migration_demotes_typed_in_demonstrated_and_leaves_signed_rows_alone():
    from django.apps import apps

    dep = _deployment()
    signed = _ingested(dep)
    typed = WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="payout", status=comp.HELD, basis=comp.BASIS_DEMONSTRATED,
        observed_at=_now() - timedelta(hours=1),
    )
    _migration_0032().typed_in_demonstrated_is_attested(apps, None)
    assert WorkflowChainOutcome.objects.get(pk=typed.pk).basis == comp.BASIS_ATTESTED
    assert WorkflowChainOutcome.objects.get(pk=signed.pk).basis == comp.BASIS_DEMONSTRATED


def test_reversing_the_migration_refuses_while_signed_evidence_exists():
    from django.apps import apps

    module = _migration_0032()
    step = next(op for op in module.Migration.operations if op.__class__.__name__ == "RunPython")
    assert step.reverse_code is module.refuse_to_drop_signed_evidence

    module.refuse_to_drop_signed_evidence(apps, None)  # nothing signed: allowed
    _ingested(_deployment())
    with pytest.raises(RuntimeError, match="signed evidence"):
        module.refuse_to_drop_signed_evidence(apps, None)
