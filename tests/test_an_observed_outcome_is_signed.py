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
    assert composition_signal(dep) == comp.READY

    stat = os.stat(keyring)
    keyring.write_text(athena)
    os.utime(keyring, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert os.stat(keyring).st_size == stat.st_size
    assert os.stat(keyring).st_mtime_ns == stat.st_mtime_ns

    assert composition_signal(dep) == comp.NEEDS_MORE_EVIDENCE
    keyring.write_text(achilles)
    assert composition_signal(dep) == comp.READY, "and rotating back is seen too"


@pytest.mark.parametrize("damage", ["deleted", "corrupted", "not-utf8", "nested"])
def test_a_keyring_gone_or_damaged_after_a_good_read_trusts_nothing(keyring, damage):
    dep = _deployment()
    _approved(dep, "refund-over-limit")
    _ingested(dep)
    assert composition_signal(dep) == comp.READY, "a good read first, so a cache exists"

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

    assert client.post(_url(dep), _signed(dep, observed_at=_now() - timedelta(minutes=2)), format="json").status_code == 201
    assert _stored(dep) == Deployment.Decision.READY

    # Widening the approved set moves it: the new workflow never reported.
    payout = {"slug": "payout", "name": "Payout"}
    assert client.put(_approved_url(dep), {"workflows": [refund, payout]}, format="json").status_code == 200
    assert _stored(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    # And narrowing it back moves it back.
    assert client.put(_approved_url(dep), {"workflows": [refund]}, format="json").status_code == 200
    assert _stored(dep) == Deployment.Decision.READY

    violated = _signed(dep, status=oc.VIOLATED, observed_at=_now() - timedelta(seconds=10))
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
    Deployment.objects.filter(pk=untouched.pk).update(decision=Deployment.Decision.READY)

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
    assert _stored(dep) == Deployment.Decision.READY


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

    def recording(deployment, **kw):
        seen.append(connection.in_atomic_block)
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
    assert _stored(dep) == Deployment.Decision.READY

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
    assert _stored(dep) == Deployment.Decision.READY
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
    assert _stored(dep) == Deployment.Decision.READY
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
