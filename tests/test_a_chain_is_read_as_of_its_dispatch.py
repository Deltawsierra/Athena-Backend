"""An authority chain is read as of its dispatch (authority chain, part 5 of the 7 Oct decision).

On master (d73fe0c) a chain's ``under_policy`` and ``invokes`` hops were read LIVE,
against the approval, served route and tool contracts in force when the decision was
computed, and the gate's permit was matched by workflow alone. So:

* a re-approval after an effect unproved an effect that was properly authorised;
* an effect dispatched under an approval already superseded read proven once that
  approval was restored.

Now Achilles signs the state its dispatch ran under into the observed effect
(``mythos.observed-effect/v2``: its own epoch, operator policy and instant, and the
approval, contracts, route and sign-in and grant digests it was presented under),
this backend keeps an append-only history of the approvals (``ApprovalVersion``) beside
the contracts' (``ToolContract``) and binds the route serving at the dispatch instant
when it records the effect, and both hops are proven against that:

* a re-approval or contract change after the effect leaves it proven, citing v1;
* an effect dispatched after its approval was superseded reads unproven, named;
* a missing or unverifiable dispatch-time record reads unproven, never live;
* a tampered dispatch-time field fails the signature;
* when the gate saw a sign-in or a grant, only those records prove the person hops;
* nothing added stands on a stop's path.
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
from django.db import connection
from django.test.utils import CaptureQueriesContext
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import composition as comp
from assurance import observed_effects, observed_outcomes
from assurance.decision import decision_support
from assurance.models import ApprovalVersion, ApprovalVersionRewriteRefused, ApprovedWorkflow, WorkflowChainOutcome
from assurance.served_route import serving_route_now
from tests import signed_chains
from tests.test_an_observed_effect_proves_the_produces_hop import TOKEN, _send
from tests.test_sign_in_and_delegation_prove_the_person_hops import (
    TOKENS,
    _chains,
    _grant,
    _person_chain,
    _service,
    _sign_in,
)
from tests.test_sign_in_and_delegation_prove_the_person_hops import _send as _send_identity
from tests.test_spine_authority_chain import WF, _base, _chain_body, _fresh, _post, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

VECTORS = Path(__file__).resolve().parent / "vectors"
User = get_user_model()


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
def collectors(monkeypatch):
    """Both identity collectors (as in the person-hop tests)."""
    clients = {}
    for kind, token in TOKENS.items():
        svc = _service(kind)
        User.objects.create_user(username=f"{kind}-collector", password="x")
        monkeypatch.setenv(svc.token_env, token)
        monkeypatch.setenv(svc.user_env, f"{kind}-collector")
        client = APIClient()
        client.credentials(**{svc.meta: token})
        clients[kind] = client
    return clients


def _now():
    return datetime.now(dt_timezone.utc)


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


def _reapprove(client, dep, description="update any customer record"):
    put = client.put(
        _base(dep) + "approved-workflows/",
        {"workflows": [{"slug": WF, "name": "Support update", "description": description,
                        "tools": [{"kind": "mcp_server", "identifier": "crm-mcp"}]}]},
        format="json",
    )
    assert put.status_code == 200, put.content


def _approval(client, dep):
    return client.get(_base(dep) + "authority-chains/").json()["approvals_in_force"][WF]


def _chain_citing(client, dep, permit, effect_row, **kw):
    body = _chain_body(client, dep, permit, **kw)
    body["effect_outcome_id"] = effect_row.outcome_id
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    return answer.json()["chains"][0]


# ------------------------------------------------------- re-approval, after and before


def test_an_effect_authorised_under_v1_stays_proven_after_a_re_approval_to_v2_citing_v1(service):
    dep, client, permit, _ = _world()
    v1 = _approval(client, dep)
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    assert evidence["schema"] == "mythos.observed-effect/v2"
    assert evidence["dispatch"]["presented"]["approval_digest"] == v1
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    chain = _chain_citing(client, dep, permit, row)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}
    lifted = _fresh(dep).decision

    _reapprove(client, dep)

    v2 = _approval(client, dep)
    assert v2 != v1
    chain = _chains(client, dep)[0]
    policy = _hops(chain)["under_policy"]
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}
    assert _codes(policy) == ["approval_in_force_at_dispatch"]
    assert v1 in policy["proven_by"][0]["detail"] and v2 not in policy["proven_by"][0]["detail"]
    assert decision_support(_fresh(dep))["claims"]["authority_chains_unproven"] == []
    assert _fresh(dep).decision == lifted


def test_an_effect_dispatched_after_v1_was_superseded_reads_unproven(service):
    dep, client, permit, _ = _world()
    v1 = _approval(client, dep)
    stale = signed_chains.live_presented(dep, WF)
    _reapprove(client, dep)
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), presented=stale)
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    body = _chain_body(client, dep, permit)
    for hop in body["hops"]:
        for end in ("from", "to"):
            if hop[end]["kind"] == "policy":
                hop[end]["version"] = v1
    body["effect_outcome_id"] = row.outcome_id
    chain = _post(client, dep, body).json()["chains"][0]
    policy = _hops(chain)["under_policy"]
    assert chain["verdict"] == "unproven"
    assert _codes(policy) == ["dispatched_under_superseded_policy"]
    assert decision_support(_fresh(dep))["claims"]["authority_chains_unproven"] != []


def test_a_contract_changed_after_the_effect_leaves_it_proven():
    from assurance.models import Asset
    from assurance.tool_contract import record_tool_contracts

    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    _chain_citing(client, dep, permit, row)
    crm = Asset.objects.get(deployment=dep, identifier="crm-mcp")
    crm.metadata = {**crm.metadata, "input_schema": {"type": "object"}}
    crm.save()
    record_tool_contracts(dep)
    chain = _chains(client, dep)[0]
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}
    assert "contract_in_force_at_dispatch" in _codes(_hops(chain)["invokes"])
    # The binding is superseded NOW, and the decision says so on its own cap; the
    # chain's effect is not unproven by it.
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_unproven"] == []


# ------------------------------------------------------- a missing record, a tamper


def test_a_v1_observed_effect_records_no_dispatch_state_and_reads_unproven_never_live(service):
    dep, client, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), schema="v1")
    assert _send(service, dep, envelope, evidence).status_code == 201, "v1 stays readable"
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    assert row.dispatch_route_fingerprint == ""
    chain = _chain_citing(client, dep, permit, row)
    hops = _hops(chain)
    assert _codes(hops["produces"]) == ["observed_effect"], "it still proves produces"
    assert _codes(hops["under_policy"]) == ["dispatch_state_unrecorded"]
    assert "dispatch_state_unrecorded" in _codes(hops["invokes"])
    assert chain["verdict"] == "unproven"


def test_a_dispatch_whose_route_the_record_cannot_place_reads_unproven(service):
    # The effect arrives after the served route moved: the route at its dispatch
    # instant cannot be shown, so nothing is bound and the invocation is unproven.
    from assurance.models import Asset

    dep, client, permit, _ = _world()
    left = _now() - timedelta(seconds=30)
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, left)
    Asset.objects.create(deployment=dep, kind="model", name="gpt-x", identifier="gpt-x",
                         classification="approved", assessed_at=_now(), metadata={"model_revision": "2"})
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    assert row.dispatch_route_fingerprint == ""
    invokes = _hops(_chain_citing(client, dep, permit, row))["invokes"]
    assert invokes["verdict"] == "unproven"
    assert any(r["code"] == "dispatch_state_unrecorded" and "served route" in r["detail"] for r in invokes["reasons"])


def test_the_route_serving_at_the_dispatch_instant_is_bound_when_the_effect_is_recorded(service):
    dep, client, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    assert row.dispatch_route_fingerprint == serving_route_now(dep) != ""


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("dispatch", "presented", "approval_digest"), "a2" * 32),
        (("dispatch", "epoch"), "running#0.9"),
        (("dispatch", "dispatched_at"), "2026-10-07T00:00:00.000000Z"),
        (("dispatch", "presented", "contracts"), []),
    ],
    ids=["approval", "epoch", "instant", "contracts"],
)
def test_a_tampered_dispatch_time_field_fails_the_signature(service, path, value):
    dep, client, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    edited = json.loads(json.dumps(evidence))
    target = edited
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    observed_effects.validate_evidence(edited)

    # Posted beside the envelope that signed the original: refused, nothing recorded.
    refused = _send(service, dep, envelope, edited)
    assert refused.status_code == 400
    assert "not the document the signature names" in json.dumps(refused.json())
    assert not WorkflowChainOutcome.objects.filter(effect_dispatch_id=evidence["dispatch_id"]).exists()

    # Recorded genuinely, then edited in the row: the document no longer matches its
    # signed digest, so it proves nothing and records no dispatch state.
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    WorkflowChainOutcome.objects.filter(pk=row.pk).update(effect_evidence=edited)
    hops = _hops(_chain_citing(client, dep, permit, row))
    assert _codes(hops["produces"]) == ["effect_evidence_unread"]
    assert _codes(hops["under_policy"]) == ["dispatch_state_unrecorded"]


# ------------------------------------------------- the person hops, end to end


def test_a_person_started_chain_stays_proven_across_a_later_re_approval(collectors, service):
    dep, client, permit, _ = _world()
    effect_at = _now()
    sign_in = _sign_in(dep, effect_at)
    grant = _grant(dep, effect_at)
    assert _send_identity(collectors["authentication"], dep, "authentication", *sign_in).status_code == 201
    assert _send_identity(collectors["delegation"], dep, "delegation", *grant).status_code == 201
    # The gate saw this sign-in and this grant at dispatch.
    presented = signed_chains.live_presented(
        dep, WF, assertion=sign_in[1]["assertion_digest"], grant=grant[1]["grant_digest"]
    )
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, effect_at, presented=presented)
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    chain = _person_chain(client, dep, permit, row)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}
    v1 = _approval(client, dep)

    _reapprove(client, dep)

    chain = _chains(client, dep)[0]
    hops = _hops(chain)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in hops.items()}
    assert {r: _codes(h) for r, h in hops.items()} == {
        "authenticated_as": ["authentication"],
        "delegates_to": ["delegation"],
        "under_policy": ["approval_in_force_at_dispatch"],
        "invokes": ["contract_in_force_at_dispatch", "route_at_dispatch", "declared_edge"],
        "through_identity": ["declared_identity"],
        "performs": ["declared_permission", "within_approval", "gate_permit"],
        "produces": ["observed_effect"],
    }
    assert v1 in hops["under_policy"]["proven_by"][0]["detail"]
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_unproven"] == support["claims"]["authority_chains_missing"] == []
    assert support["claim_cap"] is None


def test_when_the_gate_saw_another_sign_in_the_person_hop_reads_unproven(collectors, service):
    dep, client, permit, _ = _world()
    effect_at = _now()
    assert _send_identity(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at)).status_code == 201
    assert _send_identity(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at)).status_code == 201
    presented = signed_chains.live_presented(dep, WF, assertion="sha256:" + "6c" * 32, grant="sha256:" + "7d" * 32)
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, effect_at, presented=presented)
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    hops = _hops(_person_chain(client, dep, permit, row))
    assert _codes(hops["authenticated_as"]) == ["authentication_not_dispatched"]
    assert _codes(hops["delegates_to"]) == ["delegation_not_dispatched"]


# ----------------------------------------------------------------- the history


def test_every_approval_write_appends_a_version_and_the_history_is_append_only():
    dep, client, _, _ = _world()
    first = list(ApprovalVersion.objects.filter(deployment=dep, workflow=WF))
    assert [v.digest for v in first] == [_approval(client, dep)]
    _reapprove(client, dep)
    _reapprove(client, dep)  # unchanged: nothing appended
    versions = list(ApprovalVersion.objects.filter(deployment=dep, workflow=WF).order_by("in_force_from", "id"))
    assert [v.digest for v in versions] == [first[0].digest, _approval(client, dep)]
    assert versions[1].tools == [["mcp_server", "crm-mcp", versions[1].tools[0][2]]]
    put = client.put(_base(dep) + "approved-workflows/", {"workflows": []}, format="json")
    assert put.status_code == 200, put.content
    assert ApprovalVersion.objects.filter(deployment=dep, workflow=WF).order_by("in_force_from", "id").last().digest == ""
    with pytest.raises(ApprovalVersionRewriteRefused):
        versions[0].save()
    with pytest.raises(ApprovalVersionRewriteRefused):
        versions[0].delete()


def test_an_approval_no_signal_saw_is_noted_by_the_next_decision_refresh():
    from assurance.decision import refresh_stored_decisions

    dep, client, _, _ = _world()
    ApprovedWorkflow.objects.bulk_create([ApprovedWorkflow(deployment=dep, slug="quiet", name="Quiet")])
    assert not ApprovalVersion.objects.filter(deployment=dep, workflow="quiet").exists()
    refresh_stored_decisions([dep.pk])
    assert ApprovalVersion.objects.filter(deployment=dep, workflow="quiet").count() == 1


# ------------------------------------------------------------------- the safety


def test_a_pause_reads_and_writes_no_dispatch_history_and_still_wins(service):
    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    _chain_citing(client, dep, permit, row)
    with CaptureQueriesContext(connection) as captured:
        paused = client.post(_base(dep) + "recompute/", {"paused": True}, format="json")
    assert paused.status_code == 200, paused.content
    assert _fresh(dep).decision == "paused"
    touched = [q["sql"] for q in captured if "approvalversion" in q["sql"].lower()]
    assert touched == [], "a pause waits on no approval history"


def test_the_observed_effects_route_is_still_no_stop():
    from safety import stops

    assert set(stops.NOT_STOPS["deployment-observed-effects"]) == {"POST"}
    assert "deployment-observed-effects" not in stops.STOP_ROUTES


# ------------------------------------------------------- the shared schema, v2


def _vectors(name):
    return json.loads((VECTORS / name).read_text())


def _envelope(hexed):
    return {
        "payloadType": hexed["payloadType"],
        "payload": base64.b64encode(bytes.fromhex(hexed["payload_hex"])).decode(),
        "signatures": [
            {"keyid": s["keyid"], "sig": base64.b64encode(bytes.fromhex(s["sig_hex"])).decode()}
            for s in hexed["signatures"]
        ],
    }


def test_this_backend_verifies_the_v2_conformance_vector_achilles_signed():
    v = _vectors("observed-effect-v2.json")
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(v["effect_key_phrase"].encode()).digest())
    raw = oc.raw_public_key(key)
    assert raw.hex() == v["effect_public_key_hex"]
    verdict = oc.verify_outcome(_envelope(v["envelope"]), {oc.key_id_for(raw): oc.TrustedKey(raw, v["effect_engine"])})
    assert verdict.verdict == oc.AUTHENTIC, verdict.reason
    assert observed_effects.examine(verdict.outcome, v["evidence"]) == ""
    assert oc.evidence_digest_of(v["evidence"]) == v["evidence_digest"] == verdict.outcome["evidence_digest"]
    assert v["evidence"]["schema"] == observed_effects.EVIDENCE_SCHEMA == "mythos.observed-effect/v2"
    # The dispatch state reads as the rule reads it.
    from assurance.authority_chain_records import dispatch_state

    class Row:
        dispatch_route_fingerprint = "e5" * 32

    state = dispatch_state(v["evidence"], Row())
    assert state.epoch == state.permit_epoch == v["inputs"]["gate_result"]["epoch"]
    assert state.approval_digest == v["inputs"]["authority"]["approval_digest"]
    assert state.contracts == {("mcp_server", "crm-mcp"): "c0" * 32}
    assert state.dispatched_at == observed_outcomes._instant(v["inputs"]["dispatched_at"])


def test_every_invalid_v2_vector_is_refused_and_v1_stays_readable():
    v2 = _vectors("observed-effect-v2.json")
    assert observed_effects.validate_evidence(v2["evidence"]) == v2["evidence"]
    assert len(v2["invalid"]) >= 19
    for case in v2["invalid"]:
        with pytest.raises(observed_effects.EvidenceRefused):
            observed_effects.validate_evidence(case["evidence"])
    v1 = _vectors("observed-effect-v1.json")
    assert observed_effects.validate_evidence(v1["evidence"]) == v1["evidence"]
    assert comp.EVIDENCE_OBSERVED_EFFECT == "observed_effect"
