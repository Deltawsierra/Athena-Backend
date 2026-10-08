"""The approval the gate read itself is gate-attested (authority chain short 3, option b).

Until now ``under_policy`` read only what the DISPATCHER presented
(``mythos.observed-effect/v2``'s ``presented.approval_digest``), signed by Achilles
"as presented": proven against this backend's history, but attested by nothing that
admitted the action, and a caller that presented none left the chain unproven.

On the owner's 8 Oct decision Achilles' gate reads the approval in force from this
backend itself, at decide time (``GET .../workflows/<slug>/approval-in-force/``,
:mod:`assurance.gate_approval`), and signs the version id and digest it read into the
observed effect (``mythos.observed-effect/v3``, ``dispatch.verified.workflow_approval``).
``under_policy`` now reads that reading first:

* it matches the history row in force at the dispatch: proven, gate-attested
  (``approval_attested_in_force_at_dispatch``), citing the signed record and the row;
* it contradicts the history -- the version not on record with that digest, or another
  digest presented beside it: broken (``approval_digest_contradicts_gate``), and the
  decision is held at ``needs_remediation``;
* the approval moved between the read and the dispatch: unproven, superseded;
* only a presented digest (a v2 document, or a gate with no link): exactly as before,
  and the reading says "presented";
* no digest: unproven, as before;
* a forged gate reading never reads proven.

On master the v3 document is refused, the route does not exist and the rule has no
gate-attested reading, so these fail there.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import authority_chain as rule
from assurance import gate_approval, observed_effects, observed_outcomes
from assurance.authority_chain_records import dispatch_state
from assurance.models import ApprovalVersion, ApprovedWorkflow, Deployment, WorkflowChainOutcome
from safety import stops
from tests import signed_chains
from tests.test_an_observed_effect_proves_the_produces_hop import TOKEN, _send
from tests.test_spine_authority_chain import WF, _base, _chain_body, _fresh, _post, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

VECTORS = Path(__file__).resolve().parent / "vectors"
User = get_user_model()
READ_TOKEN = "gate-approval-read-token-for-tests-0123456789"  # pragma: allowlist secret


@pytest.fixture
def service(monkeypatch):
    """The observed-effect service (as in the produces-hop tests)."""
    User.objects.create_user(username="effect-service", password="x")
    monkeypatch.setenv(observed_effects.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(observed_effects.USER_ENV, "effect-service")
    client = APIClient()
    client.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN=TOKEN)
    return client


@pytest.fixture
def gate(monkeypatch):
    """Achilles' gate, with its approval-read credential."""
    User.objects.create_user(username="gate-reader", password="x")
    monkeypatch.setenv(gate_approval.TOKEN_ENV, READ_TOKEN)
    monkeypatch.setenv(gate_approval.USER_ENV, "gate-reader")
    client = APIClient()
    client.credentials(HTTP_X_GATE_APPROVAL_TOKEN=READ_TOKEN)
    return client


def _now():
    return datetime.now(dt_timezone.utc)


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _readings(hop):
    return hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"]


def _codes(hop):
    return [r["code"] for r in _readings(hop)]


def _reapprove(client, dep, description):
    put = client.put(
        _base(dep) + "approved-workflows/",
        {"workflows": [{"slug": WF, "name": "Support update", "description": description,
                        "tools": [{"kind": "mcp_server", "identifier": "crm-mcp"}]}]},
        format="json",
    )
    assert put.status_code == 200, put.content


def _record(service, dep, permit, **kw):
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), **kw)
    sent = _send(service, dep, envelope, evidence)
    assert sent.status_code == 201, sent.content
    return WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"]), evidence


def _chain(client, dep, permit, row, **kw):
    body = _chain_body(client, dep, permit, **kw)
    body["effect_outcome_id"] = row.outcome_id
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    return answer.json()["chains"][0]


def _reading(dep, **changes):
    reading = signed_chains.live_reading(dep, WF, _now() - timedelta(minutes=1, seconds=1))
    assert reading is not None
    return {**reading, **changes}


# ------------------------------------------------------------ the four readings


def test_a_gate_reading_matching_the_row_in_force_at_dispatch_is_proven_gate_attested(service):
    dep, client, permit, _ = _world()
    reading = _reading(dep)
    row, evidence = _record(service, dep, permit, schema="v3", reading=reading)
    assert evidence["schema"] == "mythos.observed-effect/v3"

    chain = _chain(client, dep, permit, row)

    policy = _hops(chain)["under_policy"]
    assert policy["verdict"] == "proven", _readings(policy)
    assert _codes(policy) == ["approval_attested_in_force_at_dispatch"]
    detail = policy["proven_by"][0]["detail"]
    version = ApprovalVersion.objects.filter(deployment=dep, workflow=WF).order_by("in_force_from", "id").last()
    # Cites the signed record and the history row.
    assert row.outcome_id in detail and f"version {version.id}" in detail and reading["digest"] in detail
    assert reading["version"] == str(version.id)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}


def test_a_gate_reading_that_contradicts_the_history_is_broken_and_holds_the_decision(service):
    dep, client, permit, _ = _world()
    version = ApprovalVersion.objects.filter(deployment=dep, workflow=WF).last()
    cases = {
        "another digest for the version": _reading(dep, digest="c3" * 32),
        "a version not on record": _reading(dep, version=str(version.id + 1000)),
    }
    for why, reading in cases.items():
        row, _ = _record(
            service, dep, permit, schema="v3", reading=reading,
            presented={**signed_chains.live_presented(dep, WF), "approval_digest": None},
        )
        chain = _chain(client, dep, permit, row)
        policy = _hops(chain)["under_policy"]
        assert policy["verdict"] == "broken", (why, _readings(policy))
        assert "approval_digest_contradicts_gate" in _codes(policy), why
        assert chain["verdict"] == "broken", why
    assert _fresh(dep).decision == Deployment.Decision.NEEDS_REMEDIATION


def test_a_presented_digest_contradicting_the_gate_reading_is_broken(service):
    dep, client, permit, _ = _world()
    presented = {**signed_chains.live_presented(dep, WF), "approval_digest": "d4" * 32}
    row, _ = _record(service, dep, permit, schema="v3", reading=_reading(dep), presented=presented)

    policy = _hops(_chain(client, dep, permit, row))["under_policy"]

    assert policy["verdict"] == "broken" and _codes(policy) == ["approval_digest_contradicts_gate"]
    assert "presented" in policy["reasons"][0]["detail"]


def test_an_approval_that_moved_between_the_read_and_the_dispatch_reads_superseded(service):
    dep, client, permit, _ = _world()
    read_before = _reading(dep)  # the gate read v1 at its decide
    presented_v1 = signed_chains.live_presented(dep, WF)  # and the dispatcher presented v1
    _reapprove(client, dep, "rewritten after the gate read it")  # v2, before the dispatch

    row, _ = _record(service, dep, permit, schema="v3", reading=read_before, presented=presented_v1)
    policy = _hops(_chain(client, dep, permit, row))["under_policy"]

    assert policy["verdict"] == "unproven", _readings(policy)
    assert "dispatched_under_superseded_policy" in _codes(policy)
    assert "attested by the gate" in policy["reasons"][-1]["detail"]


def test_a_re_approval_after_the_effect_leaves_the_gate_attested_hop_proven(service):
    dep, client, permit, _ = _world()
    row, _ = _record(service, dep, permit, schema="v3", reading=_reading(dep))
    chain = _chain(client, dep, permit, row)
    _reapprove(client, dep, "rewritten after the effect")

    again = client.get(_base(dep) + "authority-chains/").json()["chains"]
    policy = _hops(next(c for c in again if c["uuid"] == chain["uuid"]))["under_policy"]
    assert _codes(policy) == ["approval_attested_in_force_at_dispatch"], _readings(policy)


def test_only_a_presented_digest_reads_exactly_as_before_and_says_presented(service):
    dep, client, permit, _ = _world()
    for schema, extra in (("v2", {}), ("v3", {"reading": None})):
        row, _ = _record(service, dep, permit, schema=schema, **extra)
        policy = _hops(_chain(client, dep, permit, row))["under_policy"]
        assert policy["verdict"] == "proven", (schema, _readings(policy))
        assert _codes(policy) == ["approval_in_force_at_dispatch"], schema
        assert "presented by the dispatcher, not attested by the gate" in policy["proven_by"][0]["detail"]


def test_no_digest_at_all_reads_unproven_as_before(service):
    dep, client, permit, _ = _world()
    presented = {**signed_chains.live_presented(dep, WF), "approval_digest": None}
    for schema, extra in (("v2", {}), ("v3", {"reading": None})):
        row, _ = _record(service, dep, permit, schema=schema, presented=presented, **extra)
        policy = _hops(_chain(client, dep, permit, row))["under_policy"]
        assert policy["verdict"] == "unproven" and _codes(policy) == ["dispatch_state_unrecorded"], schema


# --------------------------------------------------- a forged reading never proves


def test_a_gate_reading_signed_by_a_key_this_backend_does_not_trust_is_refused(service):
    dep, client, permit, _ = _world()
    forger = Ed25519PrivateKey.generate()
    envelope, evidence = signed_chains.observed_effect(
        dep, WF, permit.outcome_id, _now(), schema="v3", reading=_reading(dep), key=forger
    )

    refused = _send(service, dep, envelope, evidence)

    assert refused.status_code == 400, refused.content
    assert not WorkflowChainOutcome.objects.filter(effect_dispatch_id=evidence["dispatch_id"]).exists()


def test_a_gate_reading_edited_after_it_was_signed_never_reads_proven(service):
    dep, client, permit, _ = _world()
    row, evidence = _record(service, dep, permit, schema="v3", reading=_reading(dep, digest="c3" * 32))
    # The stored document edited to say what the history holds: it no longer matches
    # its signed digest, so nothing in it is read.
    edited = json.loads(json.dumps(evidence))
    edited["dispatch"]["verified"]["workflow_approval"]["digest"] = signed_chains.live_presented(dep, WF)[
        "approval_digest"
    ]
    WorkflowChainOutcome.objects.filter(pk=row.pk).update(effect_evidence=edited)

    policy = _hops(_chain(client, dep, permit, row))["under_policy"]

    assert policy["verdict"] != "proven", _readings(policy)
    assert _codes(policy) == ["dispatch_state_unrecorded"]


# ------------------------------------------------------------- the read route


def test_the_gate_reads_the_approval_in_force_with_its_version_and_digest(gate):
    dep, client, _permit, _ = _world()
    before = ApprovalVersion.objects.count()

    answer = gate.get(_base(dep) + f"workflows/{WF}/approval-in-force/")

    assert answer.status_code == 200, answer.content
    body = answer.json()
    latest = ApprovalVersion.objects.filter(deployment=dep, workflow=WF).order_by("in_force_from", "id").last()
    assert body == {
        "deployment": str(dep.uuid),
        "workflow": WF,
        "version": str(latest.id),
        "digest": signed_chains.live_presented(dep, WF)["approval_digest"],
        "in_force_from": latest.in_force_from.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    assert body["digest"] == latest.digest
    assert ApprovalVersion.objects.count() == before, "a read wrote the history"


def test_no_approval_in_force_and_a_history_not_level_are_refused(gate):
    dep, client, _permit, _ = _world()
    assert gate.get(_base(dep) + "workflows/no-such-workflow/approval-in-force/").status_code == 404
    missing = gate.get(f"/api/assurance/deployments/{'0' * 8}-0000-4000-8000-{'0' * 12}/workflows/{WF}/approval-in-force/")
    assert missing.status_code == 404
    # An approval moved by a write no signal sees: its history is not level with it.
    ApprovedWorkflow.objects.filter(deployment=dep, slug=WF).update(description="moved by a bulk update")
    stale = gate.get(_base(dep) + f"workflows/{WF}/approval-in-force/")
    assert stale.status_code == 409 and stale.json()["code"] == gate_approval.HISTORY_NOT_LEVEL
    # Withdrawn: none in force.
    ApprovedWorkflow.objects.filter(deployment=dep, slug=WF).delete()
    gone = gate.get(_base(dep) + f"workflows/{WF}/approval-in-force/")
    assert gone.status_code == 404 and gone.json()["code"] == gate_approval.NO_APPROVAL_IN_FORCE


def test_only_the_gates_read_credential_reads_and_it_reads_nothing_else(gate, service, monkeypatch):
    dep, client, permit, _ = _world()
    url = _base(dep) + f"workflows/{WF}/approval-in-force/"
    assert APIClient().get(url).status_code == 401
    assert client.get(url).status_code == 403  # an operator, an admin, is not the gate
    # The observed-effect service's credential cannot read an approval...
    assert service.get(url).status_code in (401, 403)
    # ...and the gate's read credential cannot post an observed effect.
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), schema="v3")
    assert _send(gate, dep, envelope, evidence).status_code in (401, 403)


def test_a_read_credential_that_is_another_services_is_refused(gate, monkeypatch):
    dep, _client, _permit, _ = _world()
    monkeypatch.setenv(observed_effects.TOKEN_ENV, READ_TOKEN)
    assert gate_approval.configured_token() is None
    assert gate.get(_base(dep) + f"workflows/{WF}/approval-in-force/").status_code == 401


def test_the_read_route_is_a_read_and_no_stop():
    assert stops.NOT_STOPS["deployment-approval-in-force"].keys() == {"GET"}


# ------------------------------------------------------------- the shared vector


def _envelope(hexed):
    return {
        "payloadType": hexed["payloadType"],
        "payload": base64.b64encode(bytes.fromhex(hexed["payload_hex"])).decode(),
        "signatures": [
            {"keyid": s["keyid"], "sig": base64.b64encode(bytes.fromhex(s["sig_hex"])).decode()}
            for s in hexed["signatures"]
        ],
    }


def test_this_backend_verifies_the_v3_conformance_vector_achilles_signed():
    v = json.loads((VECTORS / "observed-effect-v3.json").read_text())
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(v["effect_key_phrase"].encode()).digest())
    raw = oc.raw_public_key(key)
    assert raw.hex() == v["effect_public_key_hex"]
    verdict = oc.verify_outcome(_envelope(v["envelope"]), {oc.key_id_for(raw): oc.TrustedKey(raw, v["effect_engine"])})
    assert verdict.verdict == oc.AUTHENTIC, verdict.reason
    assert observed_effects.examine(verdict.outcome, v["evidence"]) == ""
    assert v["evidence"]["schema"] == observed_effects.EVIDENCE_SCHEMA == "mythos.observed-effect/v3"

    class Row:
        dispatch_route_fingerprint = "e5" * 32

    state = dispatch_state(v["evidence"], Row())
    reading, answer = v["inputs"]["gate_result"]["workflow_approval"], v["inputs"]["approval_in_force"]
    assert state.gate_approval == rule.GateApproval(
        deployment=answer["deployment"],
        workflow=answer["workflow"],
        version=answer["version"],
        digest=answer["digest"],
        read_at=observed_outcomes._instant(reading["read_at"]),
    )
    assert state.approval_digest == v["inputs"]["authority"]["approval_digest"] == answer["digest"]
    # The route's answer is spelt as this backend's route spells it.
    assert set(answer) == {"deployment", "workflow", "version", "digest", "in_force_from"}


def test_every_invalid_v3_vector_is_refused_and_v2_and_v1_still_read():
    v3 = json.loads((VECTORS / "observed-effect-v3.json").read_text())
    assert observed_effects.validate_evidence(v3["evidence"]) == v3["evidence"]
    assert len(v3["invalid"]) >= 28
    for case in v3["invalid"]:
        with pytest.raises(observed_effects.EvidenceRefused):
            observed_effects.validate_evidence(case["evidence"])
    for name in ("observed-effect-v2.json", "observed-effect-v1.json"):
        old = json.loads((VECTORS / name).read_text())
        assert observed_effects.validate_evidence(old["evidence"]) == old["evidence"]

    class Row:
        dispatch_route_fingerprint = ""

    v2 = json.loads((VECTORS / "observed-effect-v2.json").read_text())
    assert dispatch_state(v2["evidence"], Row()).gate_approval is None


# ------------------------------------------------------------------- the rule


T0 = datetime(2026, 10, 8, 12, 0, tzinfo=dt_timezone.utc)
D1, D2 = "a1" * 32, "b2" * 32


def _versions(*rows):
    return tuple(rule.ApprovalVersion(in_force_from=at, digest=d, record=rec) for rec, d, at in rows)


def _gate_reading(version, digest, read_at=T0 - timedelta(seconds=30)):
    return rule.GateApproval(deployment="d", workflow=WF, version=version, digest=digest, read_at=read_at)


def _policy_readings(history, gate_approval_, *, presented=D1, version=D1, at=T0):
    chain = rule.Chain(
        workflow=WF,
        hops=(rule.Hop(rule.Node("agent", "a"), rule.UNDER_POLICY, rule.Node("policy", WF, version)),),
        effect_outcome_id="effect-1",
    )
    dispatch = rule.DispatchState(
        dispatched_at=at,
        epoch="running#x.0",
        permit_epoch="running#x.0",
        approval_digest=presented,
        gate_approval=gate_approval_,
    )
    effect = rule.ObservedEffect("mcp_server", "crm-mcp", "gate-1", dispatch=dispatch)
    inputs = rule.Inputs(
        outcomes={"effect-1": rule.CitedOutcome("effect-1", WF, "held", "observed_effect", effect)},
        approval_history={WF: history},
    )
    return rule._under_policy(chain, 0, None, None, inputs, None)


def test_the_rule_reads_the_gate_reading_against_the_row_not_the_clock():
    history = _versions(("7", D1, T0 - timedelta(hours=1)))
    proven = _policy_readings(history, _gate_reading("7", D1))
    assert [(r.verdict, r.code) for r in proven] == [(rule.PROVEN, "approval_attested_in_force_at_dispatch")]
    assert "version 7" in proven[0].detail and "effect-1" in proven[0].detail

    contradicted = _policy_readings(history, _gate_reading("7", D2), presented=None, version=D2)
    assert [(r.verdict, r.code) for r in contradicted] == [(rule.BROKEN, "approval_digest_contradicts_gate")]
    unknown = _policy_readings(history, _gate_reading("8", D1))
    assert [r.code for r in unknown] == ["approval_digest_contradicts_gate"]
    presented_other = _policy_readings(history, _gate_reading("7", D1), presented=D2)
    assert [r.code for r in presented_other] == ["approval_digest_contradicts_gate"]


def test_the_rule_reads_an_approval_moved_after_the_read_as_superseded_and_a_skew_as_unrecorded():
    moved = _versions(("7", D1, T0 - timedelta(hours=1)), ("9", D2, T0 - timedelta(seconds=10)))
    superseded = _policy_readings(moved, _gate_reading("7", D1))
    assert [(r.verdict, r.code) for r in superseded] == [(rule.UNPROVEN, "dispatched_under_superseded_policy")]
    # The platform noted version 9 a second after the dispatch by its clock, though the
    # gate read it before dispatching: a skew, unproven -- never broken.
    late = _versions(("7", D1, T0 - timedelta(hours=1)), ("9", D2, T0 + timedelta(seconds=1)))
    skewed = _policy_readings(late, _gate_reading("9", D2), presented=D2, version=D2)
    assert [(r.verdict, r.code) for r in skewed] == [(rule.UNPROVEN, "dispatch_state_unrecorded")]
    # And a chain claiming another version than the gate read.
    other = _policy_readings(_versions(("7", D1, T0 - timedelta(hours=1))), _gate_reading("7", D1), version=D2)
    assert "policy_version_not_in_force" in [r.code for r in other]
    assert rule.PROVEN not in [r.verdict for r in other]


def test_the_presented_path_is_unchanged_but_says_presented():
    history = _versions(("7", D1, T0 - timedelta(hours=1)))
    readings = _policy_readings(history, None)
    assert [(r.verdict, r.code) for r in readings] == [(rule.PROVEN, "approval_in_force_at_dispatch")]
    assert "presented by the dispatcher, not attested by the gate" in readings[0].detail


def test_the_new_codes_are_published():
    for code in ("approval_attested_in_force_at_dispatch", "approval_digest_contradicts_gate"):
        assert code in rule.REASONS and code not in rule.RETIRED_REASONS
