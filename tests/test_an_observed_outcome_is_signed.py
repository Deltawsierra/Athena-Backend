"""A demonstrated chain outcome is one an engine signed, and nothing else.

Every chain status claims an exercise, and ``basis: demonstrated`` is the field
that says a run happened. Until now an operator POST could set it: fifty typed-in
``held`` rows marked demonstrated composed to READY with nothing exercised. The
engines now sign what they report (Achilles per dispatch, Athena per scan) -- which
for Achilles is a permit check, not an observed effect; that labelling is pinned in
``test_a_permit_is_not_an_observation`` -- and this suite holds the other half: the only way a demonstrated row reaches the
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
from assurance.policy import policy_pin
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
        # Now by default: signed after the deployment exists, as a run against it
        # is. One from before the route serving it was noted is bound to no route
        # (P2.2) and floors like one nobody ran, which is not what these test.
        observed_at=observed_at or _now(),
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
    workflow unexercised; signed by the engine that reported it, it does not. The
    signer here is Achilles, so what it rests on is an authorization check at
    dispatch, not an observed effect -- and the owner's ruling (#278) holds that
    at ready with restrictions, never plain READY."""
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
    assert composition_signal(dep) == comp.READY_RESTRICTED


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
    assert composition_signal(dep) == comp.READY_RESTRICTED

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


def test_a_signed_row_moved_to_another_deployment_is_not_evidence_there():
    """The same row, every column intact -- outcome_id included -- reassigned to a
    different deployment. Only the deployment the signature names separates the
    two, so this is the check that it is compared at all."""
    source, target = _deployment(), _deployment()
    _approved(target, "refund-over-limit")
    row = _ingested(source)
    assert row.rests_on_signed_evidence
    WorkflowChainOutcome.objects.filter(pk=row.pk).update(deployment=target)
    moved = WorkflowChainOutcome.objects.get(pk=row.pk)
    assert not moved.rests_on_signed_evidence
    assert composition_signal(target) == comp.NEEDS_MORE_EVIDENCE
    assert composition_for(target).basis_census[comp.BASIS_ATTESTED] == 1


def test_signed_is_a_statement_about_a_demonstrated_row_only():
    """``signed`` answers "does this row's demonstrated rest on a signature". A row
    whose basis says attested makes no such claim, whatever its columns carry, and
    must not be published as signed beside a basis that says a person asserted it."""
    dep = _deployment()
    row = _ingested(dep)
    WorkflowChainOutcome.objects.filter(pk=row.pk).update(basis=comp.BASIS_ATTESTED)
    demoted = WorkflowChainOutcome.objects.get(pk=row.pk)
    assert not demoted.rests_on_signed_evidence
    listed = _client().get(_operator_url(dep)).json()
    rows = listed["results"] if isinstance(listed, dict) and "results" in listed else listed
    rows = rows["outcomes"] if isinstance(rows, dict) and "outcomes" in rows else rows
    assert [r["signed"] for r in rows] == [False]


def test_withdrawing_a_key_withdraws_what_it_vouched_for(tmp_path, monkeypatch):
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert composition_signal(dep) == comp.READY_RESTRICTED

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


@pytest.mark.parametrize("basis", [comp.BASIS_ATTESTED, comp.BASIS_UNKNOWN, None], ids=["attested", "unknown", "omitted"])
def test_a_future_dated_typed_in_held_is_refused_and_could_not_hide_a_signed_violation(basis):
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep, status=oc.VIOLATED)
    assert composition_signal(dep) == comp.NOT_RECOMMENDED
    said = {} if basis is None else {"basis": basis}

    far = _client().post(
        _operator_url(dep),
        {"workflow": "refund-over-limit", "status": comp.HELD, "observed_at": "2099-01-01T00:00:00Z", **said},
        format="json",
    )
    assert far.status_code == 400
    assert "in the future" in json.dumps(far.json())

    # Within the skew allowance it is accepted -- and still does not displace the
    # signed violation, however much later it is dated.
    near = _client().post(
        _operator_url(dep),
        {"workflow": "refund-over-limit", "status": comp.HELD,
         "observed_at": (_now() + timedelta(minutes=1)).isoformat(), **said},
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


# ------------------------------------------------ round two


def _rows(response):
    return response.json()["outcomes"]


def test_the_skew_allowance_on_the_operator_route_is_the_signed_routes_five_minutes():
    """Just inside the allowance is accepted, just outside refused -- the bound the
    two doors share, pinned at both edges rather than only far past it."""
    assert observed_outcomes.MAX_CLOCK_SKEW == timedelta(minutes=5)
    dep = _deployment()
    client = _client()
    inside = client.post(
        _operator_url(dep),
        {"workflow": "w", "status": comp.HELD, "observed_at": (_now() + timedelta(minutes=4)).isoformat()},
        format="json",
    )
    assert inside.status_code == 200, inside.content
    outside = client.post(
        _operator_url(dep),
        {"workflow": "w", "status": comp.HELD, "observed_at": (_now() + timedelta(minutes=6)).isoformat()},
        format="json",
    )
    assert outside.status_code == 400
    assert "in the future" in json.dumps(outside.json())


def test_one_refusal_names_every_envelope_it_refuses_whatever_check_refused_it():
    """A forged envelope and a replay in one batch: both are named in the one 400.
    The envelope checks used to return first, so the replay surfaced only after
    the caller fixed the forgery and posted again."""
    dep = _deployment()
    client = _client()
    recorded = _signed(dep, workflow="refund-over-limit")
    assert client.post(_url(dep), recorded, format="json").status_code == 201

    forged = dict(_signed(dep, workflow="payout"))
    forged["signatures"] = [{**forged["signatures"][0], "sig": base64.b64encode(b"\0" * 64).decode()}]
    batch = [forged, _signed(dep, workflow="export"), recorded]
    response = client.post(_url(dep), {"envelopes": batch}, format="json")

    assert response.status_code == 400, response.content
    refused = response.json()["refused"]
    assert [r["index"] for r in refused] == [0, 2]
    assert "already recorded" in refused[1]["reason"]
    assert WorkflowChainOutcome.objects.filter(deployment=dep).count() == 1

    # The other way round: the replay first, the forgery last. The two checks
    # run in two passes, and the refusals still come back in the caller's order.
    reversed_batch = [recorded, _signed(dep, workflow="export"), forged]
    response = client.post(_url(dep), {"envelopes": reversed_batch}, format="json")
    assert response.status_code == 400, response.content
    refused = response.json()["refused"]
    assert [r["index"] for r in refused] == [0, 2]
    assert "already recorded" in refused[0]["reason"]


def test_a_row_publishes_the_basis_the_rule_relies_on_beside_the_one_it_was_written_with(tmp_path, monkeypatch):
    """``basis`` is what was written; ``basis_in_force`` is what the graph counts.
    With the signing key withdrawn the row still says demonstrated, and the graph
    counts it attested -- and the row now says so too, instead of publishing the
    more flattering answer alone."""
    dep = _deployment()
    _ingested(dep)
    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="typed", status=comp.HELD, observed_at=_now() - timedelta(hours=1)
    )
    by_workflow = {r["workflow"]: r for r in _rows(_client().get(_operator_url(dep)))}
    assert by_workflow["refund-over-limit"]["basis_in_force"] == comp.BASIS_DEMONSTRATED
    assert by_workflow["refund-over-limit"]["signed"] is True
    assert by_workflow["typed"]["basis_in_force"] == comp.BASIS_UNKNOWN
    assert by_workflow["typed"]["signed"] is False

    only_athena = tmp_path / "rotated.json"
    only_athena.write_text(_athena_only())
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(only_athena))
    withdrawn = {r["workflow"]: r for r in _rows(_client().get(_operator_url(dep)))}["refund-over-limit"]
    assert withdrawn["basis"] == comp.BASIS_DEMONSTRATED
    assert withdrawn["basis_in_force"] == comp.BASIS_ATTESTED
    assert withdrawn["signed"] is False
    assert composition_for(dep).basis_census[comp.BASIS_ATTESTED] == 1


def test_the_signed_route_response_publishes_the_basis_in_force():
    dep = _deployment()
    response = _client().post(_url(dep), _signed(dep), format="json")
    assert response.status_code == 201
    assert _rows(response)[0]["basis_in_force"] == comp.BASIS_DEMONSTRATED


# ------------------------------------------------ the keyring as it stands now


def _achilles_only():
    return json.dumps([{"engine": "achilles", "public_key": base64.b64encode(oc.raw_public_key(ACHILLES)).decode()}])


def _athena_only():
    # "athena " padded to the length of "achilles", so a rotation between the two
    # is a same-size rewrite. The engine name is not part of the key id.
    return json.dumps([{"engine": "athena  ", "public_key": base64.b64encode(oc.raw_public_key(ATHENA)).decode()}])


def test_a_same_size_in_place_rewrite_of_the_keyring_is_read_not_trusted_stale(keyring):
    """The rotation that kept a withdrawn key trusted: same path, same length,
    same mtime. The cache is keyed on the content, so it is seen."""
    import os

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    achilles, athena = _achilles_only(), _athena_only()
    assert len(achilles) == len(athena), "the test needs a same-length rotation"
    keyring.write_text(achilles)
    assert composition_signal(dep) == comp.READY_RESTRICTED

    stat = os.stat(keyring)
    keyring.write_text(athena)
    os.utime(keyring, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert os.stat(keyring).st_size == stat.st_size
    assert os.stat(keyring).st_mtime_ns == stat.st_mtime_ns

    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE
    keyring.write_text(achilles)
    assert composition_signal(dep) == comp.READY_RESTRICTED, "and rotating back is seen too"


@pytest.mark.parametrize("damage", ["deleted", "corrupted", "not-utf8", "nested"])
def test_a_keyring_gone_or_damaged_after_a_good_read_trusts_nothing(keyring, damage):
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert composition_signal(dep) == comp.READY_RESTRICTED, "a good read first, so a cache exists"

    if damage == "deleted":
        keyring.unlink()
    elif damage == "corrupted":
        keyring.write_text('[{"engine": "achilles", "public_key": "not base64!"}]')
    elif damage == "not-utf8":
        keyring.write_bytes(b"\xff\xfe" + b"\x00" * 40)
    else:
        keyring.write_text("[" * 100_000)
    assert observed_outcomes.trusted_keyring() is None
    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE


# ------------------------------------------------ the stored decision follows the chains


def _stored(dep):
    dep.refresh_from_db()
    return dep.decision


#: What one Achilles-signed held on the only approved workflow reads: an
#: authorization check -- the gate authorized the action at dispatch, and nothing
#: shows the effect happened within that authority -- so ready with restrictions at
#: best (the chain caps in the policy document). The tests below move a decision
#: off it; that it starts short of READY is not what they test.
ACHILLES_HELD = Deployment.Decision.READY_RESTRICTED


def _approved_url(dep):
    return f"/api/assurance/deployments/{dep.uuid}/approved-workflows/"


def test_every_chain_write_route_refreshes_the_stored_decision():
    """The receipt and the bundle read the STORED decision. Each route that moves
    the chains under it now moves it too."""
    dep = _deployment()
    client = _client()
    refund = {"slug": "refund-over-limit", "name": "Refund"}
    assert client.put(_approved_url(dep), {"workflows": [refund]}, format="json").status_code == 200
    # Approved and never reported: not demonstrated, and the stored decision says so.
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE

    # Signed after the deployment exists (see `_signed`); the violation below later still.
    assert client.post(_url(dep), _signed(dep), format="json").status_code == 201
    assert _stored(dep) == Deployment.Decision.READY_RESTRICTED

    # Widening the approved set moves it: the new workflow never reported.
    payout = {"slug": "payout", "name": "Payout"}
    assert client.put(_approved_url(dep), {"workflows": [refund, payout]}, format="json").status_code == 200
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    # And narrowing it back moves it back.
    assert client.put(_approved_url(dep), {"workflows": [refund]}, format="json").status_code == 200
    assert _stored(dep) == Deployment.Decision.READY_RESTRICTED

    violated = _signed(dep, status=oc.VIOLATED)
    assert client.post(_url(dep), violated, format="json").status_code == 201
    assert _stored(dep) == Deployment.Decision.NOT_RECOMMENDED


def test_an_operator_chain_write_refreshes_the_stored_decision():
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    response = _client().post(
        _operator_url(dep),
        {"workflow": "refund-over-limit", "status": comp.VIOLATED, "observed_at": _now().isoformat()},
        format="json",
    )
    assert response.status_code == 200, response.content
    assert _stored(dep) == Deployment.Decision.NOT_RECOMMENDED


def test_a_chain_write_does_not_lift_an_operators_pause():
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    Deployment.objects.filter(pk=dep.pk).update(decision=Deployment.Decision.PAUSED)
    assert _client().post(_url(dep), _signed(dep), format="json").status_code == 201
    assert _stored(dep) == Deployment.Decision.PAUSED


# ------------------------------------------------ the upgrade recomputes what the old rule decided


def _assurance_app():
    from django.apps import apps

    return apps.get_app_config("assurance")


def _typed_in_ready(**decision):
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="refund-over-limit", status=comp.HELD,
        basis=comp.BASIS_ATTESTED, observed_at=_now() - timedelta(hours=1),
    )
    Deployment.objects.filter(pk=dep.pk).update(
        decision=decision.get("decision", Deployment.Decision.READY), decision_keyring=None
    )
    return dep


def test_the_upgrade_recomputes_every_decision_the_old_rule_made_and_only_those():
    from assurance.signals import recompute_decisions_computed_under_another_rule as receiver

    dep = _typed_in_ready()
    untouched = _deployment()
    # Stamped under the rules in force: what is under test is the keyring upgrade's
    # reach, not the policy stamp's (test_an_accepted_risk_is_carried_not_removed).
    Deployment.objects.filter(pk=untouched.pk).update(
        decision=Deployment.Decision.READY, decision_policy=policy_pin()
    )

    receiver(sender=object(), using="default")
    receiver(sender=_assurance_app(), using="other")
    assert _stored(dep) == Deployment.Decision.READY, "not this app's signal, or not its database"

    receiver(sender=_assurance_app(), using="default")
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert _stored(untouched) == Deployment.Decision.READY, "a deployment with no chains is not the upgrade's to move"


def test_a_migrate_that_stopped_after_the_upgrade_still_recomputes_on_the_rerun():
    """post_migrate fires only after a whole plan succeeds. The trigger used to be
    "the marker migration was in the plan just applied", which a failed migrate
    followed by a re-run never satisfies. A NULL stamp is still NULL on the re-run."""
    from django.core.management import call_command

    dep = _typed_in_ready()
    call_command("migrate", verbosity=0)
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_the_upgrade_recompute_is_idempotent_and_moves_nothing_already_stamped():
    from assurance.signals import recompute_decisions_computed_under_another_rule as receiver

    dep = _typed_in_ready()
    receiver(sender=_assurance_app(), using="default")
    revision = Deployment.objects.get(pk=dep.pk).decision_revision
    # A stamped decision set by hand stays as it is: an unrelated migrate moves nothing.
    Deployment.objects.filter(pk=dep.pk).update(decision=Deployment.Decision.READY)
    receiver(sender=_assurance_app(), using="default")
    assert _stored(dep) == Deployment.Decision.READY
    assert Deployment.objects.get(pk=dep.pk).decision_revision == revision


def test_the_upgrade_recompute_keeps_an_operators_pause():
    from assurance.signals import recompute_decisions_computed_under_another_rule as receiver

    dep = _typed_in_ready(decision=Deployment.Decision.PAUSED)
    receiver(sender=_assurance_app(), using="default")
    assert _stored(dep) == Deployment.Decision.PAUSED


# ------------------------------------------------ the stored decision is decided under the lock


def test_a_pause_committed_while_a_chain_write_is_in_flight_is_not_lifted(monkeypatch):
    """The request read "not paused" when it loaded the deployment; an operator
    paused it before the request refreshed the stored decision. The refresh keeps
    the pause as the locked row holds it."""
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    real_ingest = observed_outcomes.ingest

    def ingest_then_operator_pauses(deployment, envelopes, **kw):
        result = real_ingest(deployment, envelopes, **kw)
        response = _client().post(
            f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
        )
        assert response.status_code == 200, response.content
        return result

    monkeypatch.setattr(observed_outcomes, "ingest", ingest_then_operator_pauses)
    assert _client().post(_url(dep), _signed(dep), format="json").status_code == 201
    assert _stored(dep) == Deployment.Decision.PAUSED


def test_a_recompute_that_does_not_name_the_pause_keeps_it_and_one_that_does_lifts_it():
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    url = f"/api/assurance/deployments/{dep.uuid}/recompute/"
    assert _client().post(url, {"paused": True}, format="json").status_code == 200
    assert _client().post(url, {}, format="json").status_code == 200
    assert _stored(dep) == Deployment.Decision.PAUSED
    assert _client().post(url, {"paused": False}, format="json").status_code == 200
    assert _stored(dep) == ACHILLES_HELD


def test_a_recompute_that_does_not_name_the_pause_leaves_it_to_the_lock(monkeypatch):
    """The route must not read the pause itself: a pause read before the row lock
    is one an operator can change in between, and the recompute would then write
    the state it read over the one they set. ``None`` defers to the locked row."""
    from assurance import views

    dep = _deployment()
    seen = []
    real = views.recompute_decision

    def recording(deployment, **kw):
        seen.append(kw.get("paused", "absent"))
        return real(deployment, **kw)

    monkeypatch.setattr(views, "recompute_decision", recording)
    url = f"/api/assurance/deployments/{dep.uuid}/recompute/"
    Deployment.objects.filter(pk=dep.pk).update(decision=Deployment.Decision.PAUSED)
    assert _client().post(url, {}, format="json").status_code == 200
    assert _client().post(url, {"paused": False}, format="json").status_code == 200
    assert seen == [None, False]


def test_the_decision_is_computed_from_inside_the_transaction_that_writes_it(monkeypatch):
    """Computed first and written after, a signed violation recorded between the
    two was overwritten by the READY computed before it arrived. The inputs are now
    read under the row lock, inside the write's transaction."""
    from django.db import connection

    from assurance import decision as decision_module

    dep = _deployment()
    seen = []
    real = decision_module.compute_decision
    # The test itself runs inside pytest-django's transaction, so "in an atomic
    # block" was always true and asserted nothing: the depth has to grow.
    depth_outside = len(connection.atomic_blocks)

    def recording(deployment, **kw):
        seen.append(len(connection.atomic_blocks) > depth_outside)
        return real(deployment, **kw)

    monkeypatch.setattr(decision_module, "compute_decision", recording)
    decision_module.recompute_decision(dep)
    assert seen == [True]


# ------------------------------------------------ a withdrawn key reaches the stored decision


def _receipt_decision(dep):
    from assurance.receipt import build_assurance_receipt

    return build_assurance_receipt(Deployment.objects.get(pk=dep.pk))["result"]["decision"]


def test_withdrawing_a_key_reaches_the_stored_decision_and_the_receipt(tmp_path, monkeypatch):
    from assurance.decision import compute_decision

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert _stored(dep) == ACHILLES_HELD

    only_athena = tmp_path / "rotated.json"
    only_athena.write_text(_athena_only())
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(only_athena))

    live = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert live == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert _receipt_decision(dep) == live
    assert _stored(dep) == live, "the receipt reconciled the stored decision, not only its own copy"


@pytest.mark.parametrize("surface", ["bundle", "incident"])
def test_the_bundle_and_the_incident_pack_reconcile_too(keyring, tmp_path, monkeypatch, surface):
    from assurance.bundle import _decision_row
    from assurance.incident import _decision

    read = {
        "bundle": lambda d: _decision_row(d)["state"],
        "incident": lambda d: _decision(d)["decision"],
    }[surface]
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert _stored(dep) == ACHILLES_HELD
    rotated = tmp_path / "rotated.json"
    rotated.write_text(_athena_only())
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(rotated))
    assert read(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_reformatted_keyring_that_trusts_the_same_keys_is_not_a_rotation(keyring):
    before = observed_outcomes.keyring_fingerprint()
    keyring.write_text(json.dumps(json.loads(keyring.read_text()), indent=4))
    assert observed_outcomes.keyring_fingerprint() == before
    keyring.write_text(_athena_only())
    assert observed_outcomes.keyring_fingerprint() != before


def _rotated_to_a_new_achilles_key():
    """A keyring that parses and trusts keys -- just not the one the stored
    outcomes were signed with. ``_athena_only`` is not this: its engine name is
    not a token, so it reads as no keyring at all, and a fingerprint that saw only
    "some keys" against "none" passed every test written against it."""
    return json.dumps(
        [
            {"engine": "achilles", "public_key": base64.b64encode(oc.raw_public_key(Ed25519PrivateKey.generate())).decode()},
            {"engine": "athena", "public_key": base64.b64encode(oc.raw_public_key(ATHENA)).decode()},
        ]
    )


def test_the_fingerprint_names_which_keys_are_trusted_not_only_whether_any_are(keyring):
    before = observed_outcomes.keyring_fingerprint()
    assert before != ""
    keyring.write_text(_rotated_to_a_new_achilles_key())
    rotated = observed_outcomes.keyring_fingerprint()
    assert rotated not in ("", before)
    # The same keys bound to other engines is a different keyring too.
    entries = json.loads(_rotated_to_a_new_achilles_key())
    swapped = [dict(e, engine={"achilles": "athena", "athena": "achilles"}[e["engine"]]) for e in entries]
    assert observed_outcomes.keyring_fingerprint(observed_outcomes._parse_keyring(json.dumps(entries).encode())) != (
        observed_outcomes.keyring_fingerprint(observed_outcomes._parse_keyring(json.dumps(swapped).encode()))
    )


@pytest.mark.parametrize("surface", ["receipt", "bundle", "incident"])
def test_a_rotation_to_other_keys_reaches_the_stored_decision_on_every_surface(keyring, surface):
    """A withdrawal where keys are still trusted: the stamp moves, so every read
    surface reconciles, and what it reads is the decision the new keyring gives."""
    from assurance.bundle import _decision_row
    from assurance.incident import _decision

    read = {
        "receipt": _receipt_decision,
        "bundle": lambda d: _decision_row(Deployment.objects.get(pk=d.pk))["state"],
        "incident": lambda d: _decision(Deployment.objects.get(pk=d.pk))["decision"],
    }[surface]
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert _stored(dep) == ACHILLES_HELD
    keyring.write_text(_rotated_to_a_new_achilles_key())
    assert read(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_deployment_without_chains_is_not_reconciled_on_read():
    from assurance.decision import current_decision

    dep = _deployment()
    Deployment.objects.filter(pk=dep.pk).update(decision=Deployment.Decision.READY, decision_keyring=None)
    assert current_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.READY
    assert Deployment.objects.get(pk=dep.pk).decision_revision == 0


# ------------------------------------------------ the gaps round three found in the tests


def test_a_refresh_that_fails_rolls_back_the_outcomes_it_was_refreshing_for(monkeypatch):
    """The operator route writes the rows and refreshes the decision in one
    transaction: rows whose decision could not be recorded are not recorded."""
    from assurance import views

    def boom(deployment):
        raise RuntimeError("the refresh failed")

    monkeypatch.setattr(views, "_refresh_stored_decision", boom)
    dep = _deployment()
    client = _client()
    client.raise_request_exception = False
    response = client.post(
        _operator_url(dep),
        {"workflow": "w", "status": comp.HELD, "observed_at": _now().isoformat()},
        format="json",
    )
    assert response.status_code == 500
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()


def test_the_cached_keyring_is_parsed_from_the_bytes_that_were_hashed(keyring, monkeypatch):
    """A second read of the file could see a newer keyring than the one hashed, and
    cache it under the old identity."""
    observed_outcomes._READ_KEYRING.clear()
    monkeypatch.setattr(
        observed_outcomes, "load_keyring",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("read the file a second time")),
    )
    trusted = observed_outcomes.trusted_keyring()
    assert trusted and {key.engine for key in trusted.values()} == {"achilles", "athena"}
# ------------------------------------------------ a body nested past the stack


@pytest.mark.parametrize("route", ["observed", "operator", "approved"])
def test_a_body_nested_past_the_stack_is_a_400_not_a_500(route):
    dep = _deployment()
    url = {"observed": _url(dep), "operator": _operator_url(dep), "approved": _approved_url(dep)}[route]
    method = "put" if route == "approved" else "post"
    # Past the interpreter's recursion limit, and no deeper: the audit middleware
    # reads the body too, and its fallback redaction is its own subject.
    import sys

    depth = sys.getrecursionlimit() + 500
    body = "[" * depth + "]" * depth
    response = getattr(_client(), method)(url, body, content_type="application/json")
    assert response.status_code == 400, response.status_code
    assert "nested too deeply" in json.dumps(response.json())


def test_the_rotation_command_brings_every_stored_decision_current(tmp_path, monkeypatch):
    from io import StringIO

    from django.core.management import call_command

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    rotated = tmp_path / "rotated.json"
    rotated.write_text(_athena_only())
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(rotated))
    out = StringIO()
    call_command("recompute_chain_decisions", stdout=out)
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert "1 decision(s) moved" in out.getvalue()


# ------------------------------------------------ the gaps round four found


def _ready_then_rotated(keyring):
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert _stored(dep) == ACHILLES_HELD
    keyring.write_text(_rotated_to_a_new_achilles_key())
    return dep


@pytest.mark.parametrize("route", ["detail", "list", "executive-summary", "operational-assurance"])
def test_every_surface_that_publishes_the_decision_publishes_the_reconciled_one(keyring, route):
    """The deployment detail and list, the executive summary and the operational
    roll-up all published the stored decision unreconciled: READY beside a
    receipt saying NEEDS_MORE_EVIDENCE for the same deployment."""
    dep = _ready_then_rotated(keyring)
    client = _client()
    base = f"/api/assurance/deployments/{dep.uuid}/"
    if route == "detail":
        body = client.get(base).json()
        got, label = body["decision"], body["decision_label"]
        assert label == Deployment.Decision(got).label
    elif route == "list":
        body = client.get("/api/assurance/deployments/").json()
        rows = body["results"] if isinstance(body, dict) else body
        got = next(row for row in rows if row["uuid"] == str(dep.uuid))["decision"]
    else:
        got = client.get(base + route + "/").json()["decision"]["decision"]
    assert got == Deployment.Decision.NEEDS_MORE_EVIDENCE == _receipt_decision(dep)


def test_an_ingest_refreshes_a_decision_whose_pause_was_lifted_after_it_loaded():
    """The ingest skipped the refresh on the pause it read when it LOADED the
    deployment; an unpause committed since left a critical finding undecided."""
    from pentest.models import PentestScan

    from assurance import ingest
    from assurance.decision import compute_decision

    dep = _deployment()
    Deployment.objects.filter(pk=dep.pk).update(decision=Deployment.Decision.PAUSED)
    loaded = Deployment.objects.get(pk=dep.pk)
    lifted = _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json")
    assert lifted.status_code == 200
    scan = PentestScan.objects.create(
        user=dep.owner,
        target_url="https://app.example/",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": [{"type": "sqli", "severity": "critical", "title": "SQLi"}]},
    )
    ingest.ingest_scan(scan, deployment=loaded)
    live = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert live not in (None, Deployment.Decision.PAUSED)
    assert _stored(dep) == live


def test_an_ingest_still_keeps_an_operators_pause():
    from pentest.models import PentestScan

    from assurance import ingest

    dep = _deployment()
    Deployment.objects.filter(pk=dep.pk).update(decision=Deployment.Decision.PAUSED)
    scan = PentestScan.objects.create(
        user=dep.owner,
        target_url="https://app.example/",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": [{"type": "sqli", "severity": "critical", "title": "SQLi"}]},
    )
    ingest.ingest_scan(scan, deployment=Deployment.objects.get(pk=dep.pk))
    assert _stored(dep) == Deployment.Decision.PAUSED


def test_the_stamp_names_the_keyring_the_decision_was_computed_under(keyring, monkeypatch):
    """One recompute read the keyring three times; a rotation landing between
    them stamped a READY computed under the old keys as current under the new."""
    from assurance import decision as decision_module

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    real = observed_outcomes.trusted_keyring
    reads = []

    def rotates_after_the_first_read():
        got = real()
        reads.append(got)
        if len(reads) == 1:
            keyring.write_text(_rotated_to_a_new_achilles_key())
        return got

    monkeypatch.setattr(observed_outcomes, "trusted_keyring", rotates_after_the_first_read)
    decision_module.recompute_decision(dep)
    assert len(reads) == 1, "the decision and its stamp are read from one keyring"
    monkeypatch.setattr(observed_outcomes, "trusted_keyring", real)
    # Computed and stamped under the OLD keyring; the new one is in force, so the
    # stamp is stale and the next read reconciles.
    assert _receipt_decision(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_no_keyring_is_a_keyring_not_a_request_to_read_one(keyring):
    assert observed_outcomes.keyring_fingerprint(None) == ""
    assert observed_outcomes.keyring_fingerprint() != ""


def test_a_current_stamp_is_read_without_a_query_or_a_write(django_assert_num_queries):
    from django.db.models import Exists, OuterRef

    from assurance.decision import current_decision
    from assurance.revision import logged_head

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    # Annotated as the list and the bundle read their rows: whether it has chains,
    # and the head of its transition log, which `current_decision` holds the row
    # to before it looks at the stamp.
    annotated = Deployment.objects.annotate(
        has_chain_outcomes=Exists(WorkflowChainOutcome.objects.filter(deployment=OuterRef("pk"))),
        **logged_head(),
    ).get(pk=dep.pk)
    revision = annotated.decision_revision
    with django_assert_num_queries(0):
        assert current_decision(annotated) == ACHILLES_HELD
    assert Deployment.objects.get(pk=dep.pk).decision_revision == revision


def test_the_fingerprint_does_not_depend_on_the_order_the_keys_are_listed_in(keyring):
    before = observed_outcomes.keyring_fingerprint()
    keyring.write_text(json.dumps(list(reversed(json.loads(keyring.read_text())))))
    assert observed_outcomes.keyring_fingerprint() == before


def test_the_rotation_command_counts_only_the_decisions_that_moved(keyring):
    from io import StringIO

    from django.core.management import call_command

    moves = _deployment()
    _approved(moves, "refund-over-limit")
    _ingested(moves)
    stays = _deployment()
    _approved(stays, "refund-over-limit")
    _ingested(stays, key=ATHENA, engine="athena")
    keyring.write_text(_rotated_to_a_new_achilles_key())
    out = StringIO()
    call_command("recompute_chain_decisions", stdout=out)
    assert _stored(moves) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert _stored(stays) == Deployment.Decision.READY
    assert "recomputed 2 deployment(s); 1 decision(s) moved" in out.getvalue()


def test_the_upgrade_recompute_waits_for_the_column_it_reads():
    """``post_migrate`` fires after every migrate, including one that leaves this
    app below 0033 -- where the stamp column does not exist, and every such
    migrate crashed in this receiver. It asks the migration state it is handed,
    not the recorder table (which a run with no migrations applied never creates).

    The state below 0033 is the live one with the column taken out, not one the
    migration loader builds: under ``--nomigrations`` the loader has no assurance
    migrations at all, and asking it for 0032 failed the test rather than the
    receiver."""
    from django.apps import apps as live_apps
    from django.db.migrations.state import ProjectState

    from assurance.signals import recompute_decisions_computed_under_another_rule as receiver

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    Deployment.objects.filter(pk=dep.pk).update(decision_keyring=None, decision=Deployment.Decision.AUDIT_INCOMPLETE)
    state = ProjectState.from_apps(live_apps)
    state.remove_field("assurance", "deployment", "decision_keyring")
    below = state.apps
    assert not any(f.name == "decision_keyring" for f in below.get_model("assurance", "Deployment")._meta.get_fields())
    receiver(sender=live_apps.get_app_config("assurance"), using="default", apps=below)
    assert _stored(dep) == Deployment.Decision.AUDIT_INCOMPLETE, "it ran as though the column were there"
    # And at the state that has the column, it does run.
    receiver(sender=live_apps.get_app_config("assurance"), using="default", apps=live_apps)
    assert _stored(dep) == ACHILLES_HELD


def test_the_admin_cannot_write_the_decision():
    from django.contrib import admin as django_admin

    model_admin = django_admin.site._registry[Deployment]
    for name in ("decision", "decision_revision", "decision_keyring"):
        assert name in model_admin.readonly_fields


@pytest.mark.parametrize("body", ["[]", "1", '"x"', "null", "true"])
def test_a_recompute_body_that_is_not_an_object_is_a_400(body):
    dep = _deployment()
    client = _client()
    client.raise_request_exception = False
    response = client.post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", body, content_type="application/json"
    )
    assert response.status_code == 400, response.content


@pytest.mark.parametrize("body", [{"a": 1}, {}, {"workflow": []}])
def test_an_object_without_the_workflow_list_does_not_clear_the_approved_set(body):
    """``PUT {"a": 1}`` read as "no rows" and emptied the set, lifting every
    approved workflow's floor. Clearing it is said on purpose."""
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    response = _client().put(_approved_url(dep), body, format="json")
    assert response.status_code == 400, response.content
    assert ApprovedWorkflow.objects.filter(deployment=dep).count() == 1
    assert _client().put(_approved_url(dep), {"workflows": []}, format="json").status_code == 200
    assert ApprovedWorkflow.objects.filter(deployment=dep).count() == 0


# ------------------------------------------------ the gaps round five found


def test_decision_support_publishes_the_reconciled_decision_under_its_own_revision(keyring):
    """It computed the decision live and published the stored revision beside it:
    after a rotation, revision 1 named READY in the store and NEEDS_MORE_EVIDENCE
    here -- one revision, two decisions, and a fence that fenced nothing."""
    from assurance.revision import read_decision

    dep = _ready_then_rotated(keyring)
    body = _client().get(f"/api/assurance/deployments/{dep.uuid}/decision-support/").json()
    stored = read_decision(Deployment.objects.get(pk=dep.pk))
    assert body["decision"] == stored["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert body["revision"] == stored["revision"]


def test_read_decision_reconciles_before_it_fences(keyring):
    from assurance.revision import read_decision

    dep = _ready_then_rotated(keyring)
    assert read_decision(dep)["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_the_deployment_list_does_not_ask_per_row_whether_a_deployment_has_chains():
    """The list reconciles each row; the annotation answers "has chains?" in the
    list query. Without it every unstamped row without chains paid an `exists()`
    on every read."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    def count(n):
        for _ in range(n):
            _deployment()
        client = _client()
        with CaptureQueriesContext(connection) as queries:
            assert client.get("/api/assurance/deployments/").status_code == 200
        return len(queries)

    few = count(2)
    many = count(8)
    assert many == few, (few, many)


# ---- Round 6: the fence, the claim writes, and flush. ----


def test_the_dispatch_fence_compares_against_the_reconciled_decision(keyring, settings):
    """A push authorized while the deployment was READY_RESTRICTED, lost, and
    reconciled to FAILED; then the keyring rotates, which withdraws the chain
    evidence under that decision. The automatic retry compared against the STORED
    decision -- still ready_restricted -- and pushed, while the receipt already said
    needs_more_evidence. Whether it pushed depended on whether a reader had happened
    to reconcile first."""
    import requests.exceptions as rex
    from cryptography.fernet import Fernet

    from assurance.decision import recompute_decision
    from assurance.dispatch import dispatch_finding, reconcile_attempt
    from assurance.models import ConnectorBinding, DispatchAttempt, Finding

    settings.ASSURANCE_CREDENTIAL_KEY = Fernet.generate_key().decode()
    pushes = []

    class _Timeout:
        def post(self, url, *, headers, json):
            raise rex.ReadTimeout("the answer never came back")

    class _Accepting:
        def post(self, url, *, headers, json):
            pushes.append(url)

            class _Response:
                status_code = 201
                text = '{"key": "SEC-1"}'

                @staticmethod
                def json():
                    return {"key": "SEC-1", "id": "1"}

                @staticmethod
                def raise_for_status():
                    return None

            return _Response()

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp-fence", finding_type="t", title="T", severity="low"
    )
    recompute_decision(dep)
    authorized = _stored(dep)
    assert authorized in (Deployment.Decision.READY, Deployment.Decision.READY_RESTRICTED)
    binding = ConnectorBinding(
        deployment=dep,
        connector="jira",
        enabled=True,
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    binding.set_secret("jira-tok")
    binding.save()

    first = dispatch_finding(finding, trigger=DispatchAttempt.Trigger.MANUAL, transport_factory=_Timeout)[0]
    assert first.policy_epoch == authorized
    reconcile_attempt(first, readback=lambda _op: False)
    first.refresh_from_db()
    assert not first.blocks_retry

    keyring.write_text(_rotated_to_a_new_achilles_key())
    retry = dispatch_finding(
        Finding.objects.get(pk=finding.pk),
        trigger=DispatchAttempt.Trigger.SEVERITY,
        transport_factory=_Accepting,
    )[0]

    assert pushes == [], "a push went out under an authority the receipt had already withdrawn"
    assert retry.outcome == DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED
    assert _receipt_decision(dep) == _stored(dep) != authorized


def _ready_claim(dep):
    from assurance.claims import derive_claims
    from assurance.models import AssuranceClaim

    derive_claims(dep)
    return AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).exclude(
        status=AssuranceClaim.ClaimStatus.CONTRADICTED
    ).first()


def test_an_operators_contradiction_reaches_the_stored_decision_and_every_surface():
    """A claim an operator contradicts caps the decision. The transition route
    wrote the claim and left the stored decision alone, so decision-support
    computed needs_remediation live under the same revision the detail and the
    receipt were still publishing READY under: one revision, two decisions."""
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert _stored(dep) == ACHILLES_HELD
    claim = _ready_claim(dep)
    assert claim is not None

    client = _client()
    moved = client.post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": "contradicted"}, format="json"
    )
    assert moved.status_code == 200, moved.content

    support = client.get(f"/api/assurance/deployments/{dep.uuid}/decision-support/").json()
    detail = client.get(f"/api/assurance/deployments/{dep.uuid}/").json()
    assert support["decision"] != ACHILLES_HELD
    assert support["decision"] == detail["decision"] == _receipt_decision(dep) == _stored(dep)
    assert support["revision"] == detail.get("decision_revision", support["revision"])


def test_re_deriving_the_claims_refreshes_the_stored_decision(monkeypatch):
    """The recompute-claims route re-derives every claim, and the decision is
    capped by them; it now refreshes the stored decision as the chain routes do."""
    from assurance import views

    dep = _deployment()
    refreshed = []
    monkeypatch.setattr(views, "_refresh_stored_decision", lambda d: refreshed.append(d.pk))
    response = _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/")
    assert response.status_code == 200, response.content
    assert refreshed == [dep.pk]


def test_the_upgrade_recompute_survives_a_flush_below_the_stamp():
    """``flush`` sends post_migrate with no migration state at all. Below 0033 the
    receiver queried the missing column and the flush failed; with no state to ask
    it asks the database, and returns."""
    from django.apps import apps as live_apps

    from assurance import signals

    sender = live_apps.get_app_config("assurance")
    real = signals._has_column
    assert real("default", Deployment._meta.db_table, "decision_keyring") is True
    assert real("default", Deployment._meta.db_table, "no_such_column") is False
    assert real("default", "no_such_table", "decision_keyring") is False

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    Deployment.objects.filter(pk=dep.pk).update(decision_keyring=None, decision=Deployment.Decision.AUDIT_INCOMPLETE)
    signals._has_column = lambda *a: False
    try:
        signals.recompute_decisions_computed_under_another_rule(sender=sender, using="default", apps=None)
    finally:
        signals._has_column = real
    assert _stored(dep) == Deployment.Decision.AUDIT_INCOMPLETE, "it ran as though the column were there"
    signals.recompute_decisions_computed_under_another_rule(sender=sender, using="default", apps=None)
    assert _stored(dep) == ACHILLES_HELD


# ---- Round 7: what the migration and mutation review found unpinned. ----


def test_the_upgrade_receiver_returns_when_the_state_has_no_assurance_models():
    """``migrate assurance zero`` hands post_migrate a state without this app's
    models. The receiver must return -- not fall through to a name the lookup never
    bound, and not recompute anything."""
    from django.db.migrations.state import ProjectState

    from assurance.signals import recompute_decisions_computed_under_another_rule as receiver

    dep = _typed_in_ready()
    receiver(sender=_assurance_app(), using="default", apps=ProjectState().apps)
    assert _stored(dep) == Deployment.Decision.READY


def test_a_missing_table_is_found_missing_without_a_query_against_it():
    """``flush`` reaches the upgrade receiver with no migration state, and the
    receiver asks the database whether the stamp column exists. It described the
    table to find out, and on PostgreSQL describing a missing table is a failing
    ``SELECT``: the error was swallowed, the caller's transaction was left aborted,
    and a ``flush`` inside ``atomic()`` was silently rolled back at COMMIT. The
    catalogue is asked first now, and nothing is sent at the table itself."""
    from django.db import connection

    from assurance import signals

    sent = []

    def spy(execute, sql, params, many, context):
        sent.append(sql)
        return execute(sql, params, many, context)

    with connection.execute_wrapper(spy):
        assert signals._has_column("default", "no_such_table", "decision_keyring") is False
    assert sent, "nothing was asked at all"
    assert not [sql for sql in sent if "no_such_table" in sql], sent
    # And whatever it does send, inside a savepoint of its own: this test runs in
    # a transaction, as the flush did, and a probe that failed for some other
    # reason must take only the savepoint with it.
    assert any(sql.startswith("SAVEPOINT") for sql in sent), sent


def test_the_decision_is_computed_from_the_locked_row_not_the_callers_copy():
    """The caller's instance can be stale: an ingest that marked the evidence
    incomplete after it was loaded must cap the decision this recompute writes."""
    from assurance.decision import recompute_decision

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert _stored(dep) == ACHILLES_HELD
    stale = Deployment.objects.get(pk=dep.pk)
    Deployment.objects.filter(pk=dep.pk).update(evidence_incomplete=True)
    assert recompute_decision(stale) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_recompute_leaves_the_callers_instance_holding_the_stamp_it_wrote(django_assert_num_queries):
    """``recompute_decision`` refreshes the caller's instance, stamp included, so the
    next ``current_decision`` on it is the read with no query -- not a second
    recompute under the row lock for a decision that is already current."""
    from assurance.decision import current_decision, recompute_decision

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    Deployment.objects.filter(pk=dep.pk).update(decision_keyring=None)
    dep.refresh_from_db()
    recompute_decision(dep)
    assert dep.decision_keyring == observed_outcomes.keyring_fingerprint()
    with django_assert_num_queries(0):
        assert current_decision(dep) == ACHILLES_HELD


def test_the_bundle_does_not_ask_per_deployment_whether_it_has_chains():
    """The bundle reconciles every deployment it publishes, and an unstamped one
    asks whether it has chains. Its one query annotates the answer; without the
    annotation every row paid an ``exists()``."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from assurance.bundle import assurance_bundle

    for _ in range(6):
        _deployment()  # unstamped, no chains: the reconcile path runs for each
    assert Deployment.objects.filter(decision_keyring__isnull=True).count() == 6
    with CaptureQueriesContext(connection) as queries:
        assurance_bundle(Deployment.objects.all())
    per_row = [
        q["sql"] for q in queries.captured_queries
        if q["sql"].startswith('SELECT 1 AS "a" FROM "assurance_workflowchainoutcome"')
    ]
    assert per_row == []


_EDGE_NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=dt_timezone.utc)


def test_the_age_window_is_the_thirty_days_it_names(keyring):
    trusted = observed_outcomes.load_keyring(str(keyring))
    dep = _deployment()
    late = _signed(dep, observed_at=_EDGE_NOW - observed_outcomes.MAX_AGE - timedelta(hours=1))
    rows, refusals = observed_outcomes.ingest(dep, [late], keyring=trusted, now=_EDGE_NOW)
    assert rows == [] and "window" in refusals[0].reason
    edge = _signed(dep, observed_at=_EDGE_NOW - observed_outcomes.MAX_AGE + timedelta(seconds=1))
    rows, refusals = observed_outcomes.ingest(dep, [edge], keyring=trusted, now=_EDGE_NOW)
    assert refusals == [] and len(rows) == 1


def test_the_skew_allowance_is_the_five_minutes_it_names(keyring):
    trusted = observed_outcomes.load_keyring(str(keyring))
    dep = _deployment()
    past = _signed(dep, observed_at=_EDGE_NOW + observed_outcomes.MAX_CLOCK_SKEW + timedelta(milliseconds=500))
    rows, refusals = observed_outcomes.ingest(dep, [past], keyring=trusted, now=_EDGE_NOW)
    assert rows == [] and "in the future" in refusals[0].reason
    edge = _signed(dep, observed_at=_EDGE_NOW + observed_outcomes.MAX_CLOCK_SKEW)
    rows, refusals = observed_outcomes.ingest(dep, [edge], keyring=trusted, now=_EDGE_NOW)
    assert refusals == [] and len(rows) == 1


def test_re_deriving_the_claims_leaves_the_stored_decision_current():
    """The route test above replaces the refresh with a recorder, so it cannot see
    WHEN the refresh runs: refreshed before the claims are re-derived, the stored
    decision is the one the OLD claims implied. This asks the property instead."""
    from assurance.decision import compute_decision

    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert _stored(dep) == ACHILLES_HELD
    response = _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/")
    assert response.status_code == 200, response.content
    live = compute_decision(Deployment.objects.get(pk=dep.pk))
    assert live != ACHILLES_HELD, "the re-derivation did not move the decision"
    assert _stored(dep) == live
