"""A signed reconciliation receipt reads a chain's ``produces`` hop back (F1).

Achilles (G3) never signs an observed effect for a dispatch whose provider answer was
lost: the effect is ``unknown``. It asks the provider's readback what became of the
dispatch's idempotency key and signs each answer with its observed-effect key as a
``mythos.effect-reconciliation/v1`` receipt, under a DSSE payload type of its own. This
backend takes them in on a route of their own (``effect-reconciliations``,
:mod:`assurance.effect_reconciliation`) and reads them beside the observed effect when a
chain's ``produces`` hop is verified (:func:`assurance.authority_chain.readback`):

* ``committed`` proves the hop, with a proof of its own (``readback``);
* ``failed`` breaks it (``effect_not_produced``): the chain never reads as produced;
* ``unknown`` leaves it unproven, the receipt cited (``effect_unknown``);
* conflicting evidence for one dispatch, a mismatched binding and a receipt whose gate
  decision is not on record yet prove nothing, each named;
* a retry is the same dispatch id under a later attempt, re-gated: the ``not_applied``
  that allowed it is no conflict with what it produced.

At the route: its own evidence kind; the outcome route and this one each refuse the
other's envelope; the payload type and the ``achilles-effect`` key are checked; one row
per receipt id (the same envelope again is 200, other bytes under the id 409); bounded;
every refusal a named 4xx; and no keyring -- or none with the effect key -- a 503 that
takes nothing in. On master (8fe186d) every test here fails: there is no route (404),
no module, no receipt model and no ``readback`` reading.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from mythos_core import outcome as oc
from mythos_core import status as vocabulary
from rest_framework.test import APIClient

from assurance import authority_chain as rule
from assurance import composition as comp
from assurance import observed_outcomes
from assurance.decision import decision_support
from assurance.models import WorkflowChainOutcome
from tests import signed_chains
from tests.test_spine_authority_chain import WF, _admin, _base, _client, _fresh, _hops, _post, _version, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
TOKEN = "observed-effect-service-token-for-tests-0123456789"  # pragma: allowlist secret
VECTOR = Path(__file__).resolve().parent / "vectors" / "effect-reconciliation-v1.json"


def _er():
    """The module this change adds, imported when a test reads it: so on a checkout
    without it each test here fails on its own, rather than the file failing to load."""
    from assurance import effect_reconciliation

    return effect_reconciliation


def _receipts():
    from assurance.models import EffectReconciliationReceipt

    return EffectReconciliationReceipt.objects


def _rewrite_refused():
    from assurance.models import EffectReconciliationRewriteRefused

    return EffectReconciliationRewriteRefused


@pytest.fixture
def service(monkeypatch):
    """The observed-effect service: its credential, and the account it authenticates as."""
    from assurance import observed_effects

    User.objects.create_user(username="effect-service", password="x")
    monkeypatch.setenv(observed_effects.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(observed_effects.USER_ENV, "effect-service")
    client = APIClient()
    client.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN=TOKEN)
    return client


def _send(service, dep, envelope):
    return service.post(_base(dep) + "effect-reconciliations/", {"envelope": envelope}, format="json")


def _now(minutes=1):
    return datetime.now(dt_timezone.utc) - timedelta(minutes=minutes)


def _record_chain(client, dep, gate, *, effect="", effect_ref="customer-record-change"):
    hops = _hops(_version(client, dep))
    hops[-1]["to"]["ref"] = effect_ref
    body = {
        "workflow": WF,
        "hops": hops,
        "gate_outcome_id": gate,
        "observed_at": (timezone.now() - timedelta(minutes=1)).isoformat(),
        "source": "operator",
    }
    if effect:
        body["effect_outcome_id"] = effect
    resp = _post(client, dep, body)
    assert resp.status_code == 201, resp.content


def _chain(client, dep, gate=None):
    chains = client.get(_base(dep) + "authority-chains/").json()["chains"]
    if gate is None:
        assert len(chains) == 1, chains
        return chains[0]
    (found,) = [c for c in chains if c["gate_outcome_id"] == gate]
    return found


def _produces(chain):
    (hop,) = [h for h in chain["hops"] if h["relation"] == "produces"]
    return hop


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


def _receipt(dep, gate, answer, **kw):
    return signed_chains.reconciliation(dep, WF, gate, answer, **kw)


# ------------------------------------------------------------ what each answer reads


def test_a_committed_receipt_proves_produces_by_readback(service):
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    assert _codes(_produces(_chain(client, dep))) == ["effect_not_observed"]
    envelope, document = _receipt(dep, permit.outcome_id, "applied")

    resp = _send(service, dep, envelope)

    assert resp.status_code == 201, resp.content
    answer = resp.json()
    assert answer["recorded"] == 1 and answer["already_recorded"] is False
    assert answer["evidence_kind"] == comp.EVIDENCE_EFFECT_RECONCILIATION == "effect_reconciliation"
    assert answer["conclusion"] == "committed" and answer["gate_decision_recorded"] is True
    assert answer["receipt_id"] == document["receipt_id"] and answer["dispatch_id"] == document["dispatch_id"]
    # A receipt is no chain outcome and no observed effect: nothing of it is an outcome row.
    assert not WorkflowChainOutcome.objects.filter(observer_engine="achilles-effect").exists()

    chain = _chain(client, dep)
    hop = _produces(chain)
    assert hop["verdict"] == "proven", hop["reasons"]
    assert _codes(hop) == ["readback"]
    assert "proven after the fact by reading the provider back" in hop["proven_by"][0]["detail"]
    assert chain["effect_outcome_id"] is None
    (served,) = chain["reconciliations"]
    assert served == {
        "receipt_id": document["receipt_id"],
        "dispatch_id": document["dispatch_id"],
        "attempt": 1,
        "gate_outcome_id": permit.outcome_id,
        "answer": "applied",
        "conclusion": "committed",
        "read_at": document["readback"]["read_at"],
        "provider": "crm-provider",
        "verified": True,
        "binds": True,
        "why": None,
    }


def test_a_failed_receipt_breaks_produces_and_the_chain_never_reads_produced(service):
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    envelope, document = _receipt(dep, permit.outcome_id, "not_applied")
    assert _send(service, dep, envelope).status_code == 201

    chain = _chain(client, dep)
    hop = _produces(chain)
    assert hop["verdict"] == "broken" and chain["verdict"] == "broken"
    assert _codes(hop)[0] == "effect_not_produced"
    assert "answered not_applied" in hop["reasons"][0]["detail"]
    assert document["receipt_id"] in hop["reasons"][0]["detail"]
    assert hop["proven_by"] == []
    assert chain["reconciliations"][0]["conclusion"] == "failed" and chain["reconciliations"][0]["binds"] is True
    support = decision_support(_fresh(dep))
    assert _fresh(dep).decision == "needs_remediation"
    note = support["note"] if "note" in support else json.dumps(support)
    assert "readback says the effect was not produced" in note
    assert "The effect was produced through authority" not in note


def test_an_unknown_receipt_leaves_produces_unproven_and_is_cited(service):
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    envelope, document = _receipt(dep, permit.outcome_id, "cannot_say", status_code=503)
    assert _send(service, dep, envelope).status_code == 201

    hop = _produces(_chain(client, dep))
    assert hop["verdict"] == "unproven"
    assert _codes(hop) == ["effect_unknown"]
    detail = hop["reasons"][0]["detail"]
    assert "could not say" in detail and document["receipt_id"] in detail


def test_cannot_say_then_applied_for_one_attempt_proves_it(service):
    """``cannot_say`` is no answer: a later ``applied`` for the same attempt decides."""
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    dispatch, left = uuid.uuid4().hex, _now(10)
    first, _ = _receipt(dep, permit.outcome_id, "cannot_say", dispatch_id=dispatch, read_at=_now(3), dispatched_at=left)
    then, _ = _receipt(dep, permit.outcome_id, "applied", dispatch_id=dispatch, read_at=_now(2), dispatched_at=left)
    assert _send(service, dep, first).status_code == 201
    assert _send(service, dep, then).status_code == 201
    assert _codes(_produces(_chain(client, dep))) == ["readback"]


# ------------------------------------------------------------------ conflicts


def test_a_committed_and_a_failed_receipt_of_one_attempt_prove_nothing(service):
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    dispatch, left = uuid.uuid4().hex, _now(10)
    for answer in ("applied", "not_applied"):
        envelope, _ = _receipt(dep, permit.outcome_id, answer, dispatch_id=dispatch, dispatched_at=left)
        assert _send(service, dep, envelope).status_code == 201

    hop = _produces(_chain(client, dep))
    assert hop["verdict"] == "unproven"
    assert _codes(hop) == ["effect_evidence_conflicts"]
    assert "read both applied" in hop["reasons"][0]["detail"]


def test_an_observed_effect_and_a_failed_receipt_of_one_attempt_prove_nothing(service):
    dep, client, permit, _ = _world()
    effect = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    _record_chain(client, dep, permit.outcome_id, effect=effect.outcome_id)
    assert _produces(_chain(client, dep))["verdict"] == "proven"
    envelope, _ = _receipt(dep, permit.outcome_id, "not_applied", dispatch_id=effect.effect_dispatch_id)
    assert _send(service, dep, envelope).status_code == 201

    hop = _produces(_chain(client, dep))
    assert hop["verdict"] == "unproven"
    assert "effect_evidence_conflicts" in _codes(hop)
    assert effect.outcome_id in hop["reasons"][0]["detail"]


def test_two_attempts_read_applied_prove_nothing(service):
    dep, client, permit, _ = _world()
    retry = signed_chains.record_signed(dep, WF, oc.HELD, _now(1))
    dispatch = uuid.uuid4().hex
    effect = signed_chains.record_observed_effect(dep, WF, retry.outcome_id, _now(), dispatch_id=dispatch)
    _record_chain(client, dep, retry.outcome_id, effect=effect.outcome_id)
    envelope, _ = _receipt(dep, permit.outcome_id, "applied", dispatch_id=dispatch, attempt=1)
    assert _send(service, dep, envelope).status_code == 201

    hop = _produces(_chain(client, dep))
    assert hop["verdict"] == "unproven"
    assert "effect_evidence_conflicts" in _codes(hop)
    assert "2 attempts of dispatch" in hop["reasons"][-1]["detail"]


def test_a_later_attempt_read_not_applied_after_one_read_applied_proves_nothing(service):
    dep, client, permit, _ = _world()
    retry = signed_chains.record_signed(dep, WF, oc.HELD, _now(1))
    dispatch = uuid.uuid4().hex
    _record_chain(client, dep, permit.outcome_id)
    for gate, answer, attempt in ((permit.outcome_id, "applied", 1), (retry.outcome_id, "not_applied", 2)):
        envelope, _ = _receipt(
            dep, gate, answer, dispatch_id=dispatch, attempt=attempt, permit_digest="sha256:" + f"{attempt}" * 64
        )
        assert _send(service, dep, envelope).status_code == 201

    hop = _produces(_chain(client, dep))
    assert hop["verdict"] == "unproven"
    assert _codes(hop) == ["effect_evidence_conflicts"]
    assert "read not_applied" in hop["reasons"][0]["detail"] and "after attempt 1" in hop["reasons"][0]["detail"]


# --------------------------------------------------------------------- retries


def test_a_retry_after_not_applied_is_the_same_dispatch_and_proves_what_it_produced(service):
    """Attempt 1's answer was lost; its readback answered not_applied, which is what
    allowed the retry; attempt 2 (re-gated, the same dispatch id) was observed. The chain
    that cites attempt 2 is proven; the one that cites attempt 1 reads that its dispatch
    did not produce the effect, and names the attempt that did."""
    dep, client, first, _ = _world()
    second = signed_chains.record_signed(dep, WF, oc.HELD, _now(1))
    dispatch = uuid.uuid4().hex
    envelope, _ = _receipt(dep, first.outcome_id, "not_applied", dispatch_id=dispatch, attempt=1)
    assert _send(service, dep, envelope).status_code == 201
    effect = signed_chains.record_observed_effect(dep, WF, second.outcome_id, _now(), dispatch_id=dispatch)
    _record_chain(client, dep, first.outcome_id, effect_ref="first-attempt")
    _record_chain(client, dep, second.outcome_id, effect=effect.outcome_id)

    retried = _produces(_chain(client, dep, second.outcome_id))
    assert retried["verdict"] == "proven", retried["reasons"]
    assert _codes(retried) == ["observed_effect"]
    original = _produces(_chain(client, dep, first.outcome_id))
    assert original["verdict"] == "broken"
    assert _codes(original) == ["effect_not_produced"]
    assert f"gate decision {second.outcome_id}" in original["reasons"][0]["detail"]


def test_a_retry_read_back_applied_is_proven_by_its_own_receipt(service):
    dep, client, first, _ = _world()
    second = signed_chains.record_signed(dep, WF, oc.HELD, _now(1))
    dispatch = uuid.uuid4().hex
    for gate, answer, attempt, read in ((first.outcome_id, "not_applied", 1, 4), (second.outcome_id, "applied", 2, 1)):
        envelope, _ = _receipt(
            dep, gate, answer, dispatch_id=dispatch, attempt=attempt, read_at=_now(read),
            permit_digest="sha256:" + f"{attempt}" * 64,
        )
        assert _send(service, dep, envelope).status_code == 201
    _record_chain(client, dep, second.outcome_id)

    chain = _chain(client, dep)
    hop = _produces(chain)
    assert hop["verdict"] == "proven", hop["reasons"]
    assert _codes(hop) == ["readback"] and "attempt 2" in hop["proven_by"][0]["detail"]
    assert [(r["attempt"], r["conclusion"], r["binds"]) for r in chain["reconciliations"]] == [
        (1, "failed", True),
        (2, "committed", True),
    ]


# ---------------------------------------------------------------------- binding


def test_a_receipt_before_its_gate_decision_is_stored_and_binds_once_it_is(service):
    dep, client, permit, _ = _world()
    gate = uuid.uuid4().hex
    envelope, _ = _receipt(dep, gate, "applied")

    resp = _send(service, dep, envelope)

    assert resp.status_code == 201 and resp.json()["gate_decision_recorded"] is False
    _record_chain(client, dep, gate)
    chain = _chain(client, dep)
    assert _codes(_produces(chain)) == ["reconciliation_unbound"]
    assert chain["reconciliations"][0]["binds"] is False
    assert "not on record" in chain["reconciliations"][0]["why"]

    signed_chains.record_signed(dep, WF, oc.HELD, _now(1), outcome_id=gate)

    chain = _chain(client, dep)
    assert _produces(chain)["verdict"] == "proven" and _codes(_produces(chain)) == ["readback"]
    assert chain["reconciliations"][0]["binds"] is True


def _mismatch_world(service, case):
    dep, client, permit, _ = _world()
    gate, kw, effect = permit.outcome_id, {}, ""
    if case == "tool":
        kw["tool"] = ("mcp_server", "billing-mcp")
    elif case == "action":
        kw["action"] = "customer:delete"
    elif case == "workflow":
        signed_chains.record_signed(dep, "other-flow", oc.HELD, _now(1))
        kw["workflow"] = "other-flow"
    elif case == "refused_gate":
        gate = signed_chains.record_signed(dep, WF, oc.NOT_DEMONSTRATED, _now(1)).outcome_id
    elif case == "not_a_gate":
        gate = signed_chains.record_signed(dep, WF, oc.HELD, _now(1), engine="athena").outcome_id
    elif case in ("action_digest", "permit_digest", "dispatch_id"):
        observed = signed_chains.record_observed_effect(dep, WF, gate, _now())
        effect = observed.outcome_id
        kw["dispatch_id"] = observed.effect_dispatch_id
        if case == "action_digest":
            kw["action_digest"] = "cd" * 32
        elif case == "permit_digest":
            kw["permit_digest"] = "sha256:" + "aa" * 32
        else:
            kw["dispatch_id"] = uuid.uuid4().hex
    workflow = kw.pop("workflow", WF)
    envelope, _ = signed_chains.reconciliation(dep, workflow, gate, "applied", **kw)
    assert _send(service, dep, envelope).status_code == 201
    _record_chain(client, dep, gate, effect=effect)
    return client, dep


@pytest.mark.parametrize(
    "case",
    ["tool", "action", "workflow", "refused_gate", "not_a_gate", "action_digest", "permit_digest", "dispatch_id"],
)
def test_a_receipt_that_does_not_match_the_record_proves_nothing_and_says_why(service, case):
    client, dep = _mismatch_world(service, case)
    chain = _chain(client, dep)
    hop = _produces(chain)
    assert hop["verdict"] != "proven"
    assert "reconciliation_mismatch" in _codes(hop)
    named = {"refused_gate": "did not permit", "not_a_gate": "scan evidence"}.get(case, case)
    detail = next(r["detail"] for r in hop["reasons"] if r["code"] == "reconciliation_mismatch")
    assert named in detail, detail
    assert all(not r["binds"] for r in chain["reconciliations"])


def test_a_receipt_names_its_deployment_and_two_attempts_never_share_a_number():
    """The rule, pure: a receipt naming another deployment, or two gate decisions under
    one attempt number of one dispatch, binds nothing."""
    t = datetime(2026, 10, 8, 12, 0, tzinfo=dt_timezone.utc)
    chain = rule.Chain(
        workflow=WF,
        hops=(
            rule.Hop(rule.Node("policy", WF), rule.INVOKES, rule.Node("mcp_server", "crm-mcp")),
            rule.Hop(rule.Node("mcp_server", "crm-mcp"), rule.THROUGH_IDENTITY, rule.Node("service_account", "svc-x")),
            rule.Hop(rule.Node("service_account", "svc-x"), rule.PERFORMS, rule.Node("action", "customer:update")),
            rule.Hop(rule.Node("action", "customer:update"), rule.PRODUCES, rule.Node("effect", "e")),
        ),
        gate_outcome_id="g1",
    )
    gate = rule.CitedOutcome("g1", WF, comp.HELD, comp.EVIDENCE_AUTHORIZATION_CHECK)

    def receipt(**kw):
        values = {
            "receipt_id": "r1", "deployment": "dep", "workflow": WF, "tool_kind": "mcp_server",
            "tool_identifier": "crm-mcp", "action": "customer:update", "action_digest": "ab" * 32,
            "dispatch_id": "d1", "attempt": 1, "permit_digest": "sha256:" + "ef" * 32, "gate_outcome_id": "g1",
            "dispatched_at": t, "answer": "applied", "conclusion": "committed", "provider": "p", "read_at": t,
        }
        return rule.Reconciliation(**{**values, **kw})

    def produces(*receipts, deployment="dep", outcomes=None):
        inputs = rule.Inputs(outcomes=outcomes or {"g1": gate}, reconciliations=receipts, deployment=deployment)
        return rule.verify(chain, inputs).hops[-1]

    assert produces(receipt()).verdict == rule.PROVEN
    assert [r.code for r in produces(receipt(), deployment="another").reasons] == ["reconciliation_mismatch"]
    other_gate = rule.CitedOutcome("g2", WF, comp.HELD, comp.EVIDENCE_AUTHORIZATION_CHECK)
    clash = produces(
        receipt(),
        receipt(receipt_id="r2", gate_outcome_id="g2", permit_digest="sha256:" + "aa" * 32),
        outcomes={"g1": gate, "g2": other_gate},
    )
    assert [r.code for r in clash.reasons] == ["reconciliation_mismatch"]
    assert "the same attempt under gate decision" in clash.reasons[0].detail


# ----------------------------------------------------------- the route's refusals


def test_an_outcome_envelope_is_refused_at_the_receipt_route(service):
    dep, client, permit, _ = _world()
    observed, _ = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    gate = oc.sign_outcome(
        oc.build_outcome(
            deployment=str(dep.uuid), workflow=WF, status=oc.HELD, engine="achilles", engine_version="1",
            run_id="r", evidence_digest="sha256:" + "cd" * 32, observed_at=_now(),
        ),
        signed_chains.ENGINE_KEYS["achilles"],
    )
    outcomes = WorkflowChainOutcome.objects.count()
    for envelope in (observed, gate):
        resp = _send(service, dep, envelope)
        assert resp.status_code == 400, resp.content
        reason = resp.json()["refused"][0]["reason"]
        assert "signed chain outcome, not a reconciliation receipt" in reason
        assert "observed-effects route" in reason
    assert _receipts().count() == 0
    assert WorkflowChainOutcome.objects.count() == outcomes


def test_a_receipt_is_refused_at_the_observed_effect_and_signed_outcome_routes(service):
    dep, client, permit, _ = _world()
    receipt, _ = _receipt(dep, permit.outcome_id, "applied")
    _, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    outcomes = WorkflowChainOutcome.objects.count()

    resp = service.post(_base(dep) + "observed-effects/", {"envelope": receipt, "evidence": evidence}, format="json")
    assert resp.status_code == 400, resp.content
    reason = resp.json()["refused"][0]["reason"]
    assert reason.startswith("wrong_type") and "effect-reconciliations route" in reason

    resp = client.post(_base(dep) + "chain-outcomes/observed/", receipt, format="json")
    assert resp.status_code == 400, resp.content
    assert "effect-reconciliations route" in resp.json()["refused"][0]["reason"]
    assert WorkflowChainOutcome.objects.count() == outcomes
    assert _receipts().count() == 0


@pytest.mark.parametrize(
    "signer,said",
    [("achilles", "'achilles''s key"), ("athena", "'athena''s key"), ("untrusted", "does not trust")],
)
def test_a_receipt_signed_by_any_key_but_the_effect_key_is_refused(service, signer, said):
    dep, client, permit, _ = _world()
    key = signed_chains.ENGINE_KEYS.get(signer) or Ed25519PrivateKey.generate()
    envelope, _ = _receipt(dep, permit.outcome_id, "applied", key=key)
    resp = _send(service, dep, envelope)
    assert resp.status_code == 400, resp.content
    assert said in resp.json()["refused"][0]["reason"]
    assert _receipts().count() == 0


def _retyped(envelope, declared=None, signed=None):
    """``envelope``'s receipt with the payload type it declares and the one its
    signature covers set apart."""
    payload = base64.b64decode(envelope["payload"])
    key = signed_chains.ENGINE_KEYS["achilles-effect"]
    sig = key.sign(oc.pae(signed or _er().PAYLOAD_TYPE, payload))
    return {
        "payloadType": declared or _er().PAYLOAD_TYPE,
        "payload": envelope["payload"],
        "signatures": [{"keyid": envelope["signatures"][0]["keyid"], "sig": base64.b64encode(sig).decode()}],
    }


@pytest.mark.parametrize(
    "declared,signed,said",
    [
        (oc.OUTCOME_PAYLOAD_TYPE, None, "signed chain outcome"),
        (oc.OUTCOME_PAYLOAD_TYPE, oc.OUTCOME_PAYLOAD_TYPE, "signed chain outcome"),
        ("application/vnd.mythos.other+json", None, "not a reconciliation receipt"),
        (None, oc.OUTCOME_PAYLOAD_TYPE, "does not verify"),
    ],
)
def test_a_receipt_verifies_only_under_its_own_payload_type(service, declared, signed, said):
    dep, client, permit, _ = _world()
    envelope, _ = _receipt(dep, permit.outcome_id, "applied")
    resp = _send(service, dep, _retyped(envelope, declared, signed))
    assert resp.status_code == 400, resp.content
    assert said in resp.json()["refused"][0]["reason"]
    assert _receipts().count() == 0


def test_the_same_envelope_twice_is_one_receipt_and_other_bytes_under_its_id_are_409(service):
    dep, client, permit, _ = _world()
    envelope, document = _receipt(dep, permit.outcome_id, "applied")
    assert _send(service, dep, envelope).status_code == 201
    again = _send(service, dep, envelope)
    assert again.status_code == 200, again.content
    assert again.json()["recorded"] == 0 and again.json()["already_recorded"] is True
    assert _receipts().count() == 1

    other, _ = _receipt(dep, permit.outcome_id, "not_applied", receipt_id=document["receipt_id"])
    resp = _send(service, dep, other)
    assert resp.status_code == 409, resp.content
    assert "already recorded, with other bytes" in resp.json()["refused"][0]["reason"]
    (row,) = _receipts().all()
    assert row.answer == "applied" and row.envelope == envelope


def test_a_receipt_for_another_deployment_or_outside_the_window_is_refused(service):
    dep, client, permit, _ = _world()
    for envelope, said in (
        (_receipt(dep, permit.outcome_id, "applied", deployment_uuid=str(uuid.uuid4()))[0], "not this one"),
        (_receipt(dep, permit.outcome_id, "applied", read_at=_now(-60))[0], "in the future"),
        (_receipt(dep, permit.outcome_id, "applied", read_at=_now(60 * 24 * 31))[0], "30-day window"),
    ):
        resp = _send(service, dep, envelope)
        assert resp.status_code == 400, resp.content
        assert said in resp.json()["refused"][0]["reason"]
    assert _receipts().count() == 0


def test_the_body_is_bounded_and_every_refusal_is_a_named_4xx(service):
    dep, client, permit, _ = _world()
    url = _base(dep) + "effect-reconciliations/"
    big = service.post(url, json.dumps({"envelope": "x" * (_er().MAX_BODY_BYTES + 1)}), content_type="application/json")
    assert big.status_code == 413
    assert service.post(url, "envelope=x", content_type="application/x-www-form-urlencoded").status_code == 415
    good, _ = _receipt(dep, permit.outcome_id, "applied")
    payload = base64.b64decode(good["payload"])
    key = signed_chains.ENGINE_KEYS["achilles-effect"]

    def signed(raw):
        sig = base64.b64encode(key.sign(oc.pae(_er().PAYLOAD_TYPE, raw))).decode()
        return {**good, "payload": base64.b64encode(raw).decode(), "signatures": [{**good["signatures"][0], "sig": sig}]}

    bodies = [
        {},
        {"envelope": good, "extra": 1},
        {"envelope": None},
        {"envelope": "not an envelope"},
        {"envelope": {**good, "payload": "not base64!"}},
        {"envelope": {**good, "signatures": [{**good["signatures"][0], "sig": "%%%"}]}},
        {"envelope": {**good, "signatures": []}},
        {"envelope": {**good, "signatures": good["signatures"] * 2}},
        {"envelope": {**good, "payload": "A" * (_er().MAX_PAYLOAD_B64 + 4)}},
        {"envelope": signed(b"[1, 2]")},
        {"envelope": signed(b"\xff\xfe")},
        {"envelope": signed(b"[" * 100000)},
        {"envelope": signed(json.dumps(json.loads(payload), indent=1).encode())},
    ]
    for body in bodies:
        resp = service.post(url, body, format="json")
        assert 400 <= resp.status_code < 500, (body, resp.status_code, resp.content)
        assert resp.content, body
    missing = service.post(f"/api/assurance/deployments/{uuid.uuid4()}/effect-reconciliations/", {"envelope": good}, format="json")
    assert missing.status_code == 404
    assert _receipts().count() == 0


def test_only_the_observed_effect_service_may_post(service):
    dep, client, permit, _ = _world()
    envelope, _ = _receipt(dep, permit.outcome_id, "applied")
    url = _base(dep) + "effect-reconciliations/"
    assert APIClient().post(url, {"envelope": envelope}, format="json").status_code == 401
    wrong = APIClient()
    wrong.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN="x" * 48)
    assert wrong.post(url, {"envelope": envelope}, format="json").status_code == 401
    assert _client(_admin()).post(url, {"envelope": envelope}, format="json").status_code == 403
    assert _receipts().count() == 0


def test_no_keyring_or_no_effect_key_refuses_intake_and_takes_nothing_in(service, monkeypatch, tmp_path):
    dep, client, permit, _ = _world()
    envelope, _ = _receipt(dep, permit.outcome_id, "applied")
    without = {k: v for k, v in signed_chains.ENGINE_KEYS.items() if k != "achilles-effect"}
    no_effect_key = tmp_path / "no-effect-key.json"
    signed_chains.write_keyring(no_effect_key, without)
    for setting, said in (
        (None, "no outcome keyring is configured"),
        (str(tmp_path / "missing.json"), "could not be read"),
        (str(no_effect_key), "files no key under 'achilles-effect'"),
    ):
        if setting is None:
            monkeypatch.delenv(observed_outcomes.KEYRING_ENV, raising=False)
        else:
            monkeypatch.setenv(observed_outcomes.KEYRING_ENV, setting)
        resp = _send(service, dep, envelope)
        assert resp.status_code == 503, resp.content
        assert said in resp.json()["error"]
    assert _receipts().count() == 0


# ------------------------------------------------- the read degrades to unknown


def test_a_receipt_proves_nothing_once_the_keyring_cannot_verify_it(service, monkeypatch, tmp_path):
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    signed_chains.record_reconciliation(dep, WF, permit.outcome_id, "applied")
    assert _produces(_chain(client, dep))["verdict"] == "proven"

    without = {k: v for k, v in signed_chains.ENGINE_KEYS.items() if k != "achilles-effect"}
    withdrawn = tmp_path / "withdrawn.json"
    signed_chains.write_keyring(withdrawn, without)
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(withdrawn))
    chain = _chain(client, dep)
    assert _codes(_produces(chain)) == ["effect_not_observed"]
    (served,) = chain["reconciliations"]
    assert served["verified"] is False and served["binds"] is False


def test_a_column_edited_after_the_fact_proves_nothing(service):
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    row = signed_chains.record_reconciliation(dep, WF, permit.outcome_id, "not_applied")
    assert _produces(_chain(client, dep))["verdict"] == "broken"
    _receipts().filter(pk=row.pk).update(answer="applied", conclusion="committed")
    chain = _chain(client, dep)
    assert _codes(_produces(chain)) == ["effect_not_observed"]
    assert chain["reconciliations"][0]["verified"] is False


def test_a_receipt_is_append_only():
    from tests.test_spine_authority_chain import _world as world

    dep, client, permit, _ = world()
    row = signed_chains.record_reconciliation(dep, WF, permit.outcome_id, "applied")
    with pytest.raises(_rewrite_refused()):
        row.save()
    with pytest.raises(_rewrite_refused()):
        row.delete()


# ------------------------------------------------------------------ the safety


def test_a_pause_reads_no_receipt_and_still_wins(service):
    dep, client, permit, _ = _world()
    _record_chain(client, dep, permit.outcome_id)
    signed_chains.record_reconciliation(dep, WF, permit.outcome_id, "not_applied")
    with CaptureQueriesContext(connection) as captured:
        paused = client.post(_base(dep) + "recompute/", {"paused": True}, format="json")
    assert paused.status_code == 200, paused.content
    assert _fresh(dep).decision == "paused"
    touched = [q["sql"] for q in captured if "effectreconciliationreceipt" in q["sql"].lower()]
    assert touched == [], "a pause waits on no reconciliation receipt"


def test_the_receipt_route_is_no_stop():
    from safety import stops

    assert set(stops.NOT_STOPS["deployment-effect-reconciliations"]) == {"POST"}
    assert "deployment-effect-reconciliations" not in stops.STOP_ROUTES


# --------------------------------------------------------------- the vocabulary


def test_a_receipt_is_its_own_evidence_kind_and_the_effect_key_proves_nothing_new():
    kind = comp.EVIDENCE_EFFECT_RECONCILIATION
    assert kind not in comp.EVIDENCE_KINDS and kind not in comp.IDENTITY_EVIDENCE_KINDS
    assert kind not in set(comp.SIGNER_EVIDENCE.values())
    assert comp.SIGNER_EVIDENCE["achilles-effect"] == comp.EVIDENCE_OBSERVED_EFFECT
    assert _er().EVIDENCE_KIND == kind and _er().SIGNER == "achilles-effect"
    assert _er().PAYLOAD_TYPE != oc.OUTCOME_PAYLOAD_TYPE
    assert observed_outcomes.RECONCILIATION_PAYLOAD_TYPE == _er().PAYLOAD_TYPE


def test_the_words_are_the_one_status_vocabulary_and_the_tool_kinds_the_grammar():
    assert dict(_er().CONCLUSIONS) == {
        "applied": vocabulary.COMMITTED,
        "not_applied": vocabulary.FAILED,
        "cannot_say": vocabulary.UNKNOWN,
    }
    assert _er().BASIS_OBSERVED == vocabulary.OBSERVED
    assert rule.RECONCILED_CONCLUSIONS == {vocabulary.COMMITTED, vocabulary.FAILED, vocabulary.UNKNOWN}
    assert _er().TOOL_KINDS == rule.TOOL_NODE_KINDS


# ------------------------------------------------------------- the shared vector


def _wire(hexed):
    """An envelope as posted, from the vector's hex spelling (``payload_hex``,
    ``sig_hex``); a field the vector keeps as posted is kept."""
    out = {k: v for k, v in hexed.items() if k not in ("payload_hex", "signatures")}
    if "payload_hex" in hexed:
        out["payload"] = base64.b64encode(bytes.fromhex(hexed["payload_hex"])).decode()
    if "signatures" in hexed:
        out["signatures"] = [
            {"keyid": s["keyid"], "sig": base64.b64encode(bytes.fromhex(s["sig_hex"])).decode()}
            if isinstance(s, dict) and set(s) == {"keyid", "sig_hex"}
            else s
            for s in hexed["signatures"]
        ]
    return out


def _vector_keyring(v):
    raw = bytes.fromhex(v["effect_public_key_hex"])
    gate = bytes.fromhex(v["gate_public_key_hex"])
    return {
        oc.key_id_for(raw): oc.TrustedKey(raw, v["effect_engine"]),
        oc.key_id_for(gate): oc.TrustedKey(gate, "achilles"),
    }


def test_this_backend_verifies_every_valid_receipt_achilles_signed_in_the_vector():
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(v["effect_key_phrase"].encode()).digest())
    assert oc.raw_public_key(key).hex() == v["effect_public_key_hex"]
    assert (v["schema"], v["payload_type"], v["effect_engine"]) == (_er().SCHEMA, _er().PAYLOAD_TYPE, _er().SIGNER)
    assert v["readback_conclusions"] == dict(_er().CONCLUSIONS)
    keyring = _vector_keyring(v)
    answers = set()
    for case in v["valid"]:
        envelope = _wire(case["envelope"])
        document, key_id, why = _er().verify_envelope(envelope, keyring)
        assert why == "" and document == case["document"], case["name"]
        assert key_id == oc.key_id_for(oc.raw_public_key(key))
        assert oc.canonical_bytes(document) == bytes.fromhex(case["envelope"]["payload_hex"])
        answers.add(document["readback"]["answer"])
    assert answers == set(_er().ANSWERS)
    assert any(case["document"]["attempt"] > 1 for case in v["valid"])


def test_every_invalid_receipt_and_envelope_in_the_vector_is_refused():
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    assert len(v["invalid_documents"]) >= 40 and len(v["invalid_envelopes"]) >= 14
    for case in v["invalid_documents"]:
        with pytest.raises(_er().ReceiptRefused):
            _er().validate_receipt(case["document"])
    keyring = _vector_keyring(v)
    for case in v["invalid_envelopes"]:
        document, _, why = _er().verify_envelope(_wire(case["envelope"]), keyring)
        assert document is None and why, case["why"]
