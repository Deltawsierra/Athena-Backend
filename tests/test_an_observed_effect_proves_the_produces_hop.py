"""A signed observed effect proves a chain's ``produces`` hop, from production data.

Authority chain, part 3 of the owner's 7 Oct decision. On master (da4ac8a) no
production signer maps to ``observed_effect``: #134's tests proved ``produces`` only
by trusting a made-up "collector" key. Achilles now signs one with a key of its own
(``achilles-effect``) when the dispatch that carried a permitted action out saw the
provider complete it, and posts it here with the ``mythos.observed-effect/v1``
document its digest names (:mod:`assurance.observed_effects`).

* A real-key outcome, posted by the observed-effect service, proves ``produces`` --
  and a chain whose other hops are proven lifts the effect from unproven.
* A signature by any key not mapped to ``observed_effect`` is refused.
* A replayed outcome is refused: its id, and a second observation of its dispatch.
* An observation of another workflow, tool or dispatch does not prove the hop.
* ``authenticated_as`` and ``delegates_to`` stay unproven: nothing records them yet.

On master every test here fails: there is no observed-effects route (404), no
signer maps to ``observed_effect``, and an observed effect posted as a signed
outcome is recorded with nothing to bind it to the chain it is cited by.
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

from assurance import composition as comp
from assurance import observed_outcomes
from assurance.decision import decision_support
from assurance.models import WorkflowChainOutcome
from tests import signed_chains
from tests.test_spine_authority_chain import WF, _base, _chain_body, _fresh, _post, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
TOKEN = "observed-effect-service-token-for-tests-0123456789"  # pragma: allowlist secret
VECTORS = Path(__file__).resolve().parent / "vectors" / "observed-effect-v1.json"


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


def _now(minutes=1):
    return datetime.now(dt_timezone.utc) - timedelta(minutes=minutes)


def _send(service, dep, envelope, evidence):
    return service.post(
        _base(dep) + "observed-effects/", {"envelope": envelope, "evidence": evidence}, format="json"
    )


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


# ------------------------------------------------------------ a real-key outcome


def test_a_real_key_observed_effect_proves_produces_and_lifts_the_effect(service):
    dep, client, permit, _ = _world()
    assert _fresh(dep).decision == "needs_more_evidence"
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())

    resp = _send(service, dep, envelope, evidence)

    assert resp.status_code == 201, resp.content
    recorded = resp.json()
    assert recorded["evidence_kind"] == comp.EVIDENCE_OBSERVED_EFFECT
    assert recorded["dispatch_id"] == evidence["dispatch_id"]
    row = WorkflowChainOutcome.objects.get(outcome_id=recorded["outcome_id"])
    assert row.observer_engine == "achilles-effect" and row.effect_evidence == evidence

    body = _chain_body(client, dep, permit)
    body["effect_outcome_id"] = row.outcome_id
    chain = _post(client, dep, body).json()["chains"][0]

    hops = _hops(chain)
    assert hops["produces"]["verdict"] == "proven", hops["produces"]["reasons"]
    assert [r["code"] for r in hops["produces"]["proven_by"]] == ["observed_effect"]
    assert chain["verdict"] == "proven", [h["reasons"] for h in chain["hops"] if h["verdict"] != "proven"]
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_missing"] == support["claims"]["authority_chains_unproven"] == []
    assert support["claim_cap"] is None
    assert _fresh(dep).decision == support["composition"]["signal"]


def test_sign_in_and_delegation_stay_unproven_until_they_have_a_record(service):
    """Part 4's: a chain that starts at a person still cannot be fully proven."""
    from tests.test_spine_authority_chain import _hops as hops_for, _version

    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    body = _chain_body(client, dep, permit)
    body["hops"] = hops_for(_version(client, dep), person=True)
    body["effect_outcome_id"] = row.outcome_id
    chain = _post(client, dep, body).json()["chains"][0]

    hops = _hops(chain)
    assert hops["produces"]["verdict"] == "proven"
    assert {r: hops[r]["verdict"] for r in ("authenticated_as", "delegates_to")} == {
        "authenticated_as": "unproven",
        "delegates_to": "unproven",
    }
    assert chain["verdict"] == "unproven"


# -------------------------------------------------------------- the wrong key


@pytest.mark.parametrize(
    "signer",
    ["achilles", "athena", "unclassified", "untrusted", "effect-key-as-achilles"],
)
def test_a_signature_by_a_key_not_mapped_to_observed_effect_is_refused(service, engine_keyring, signer):
    dep, client, permit, _ = _world()
    if signer == "unclassified":
        signed_chains.ENGINE_KEYS["hermes"] = Ed25519PrivateKey.generate()
        signed_chains.write_keyring(engine_keyring)
        try:
            envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), engine="hermes")
        finally:
            del signed_chains.ENGINE_KEYS["hermes"]
    elif signer == "untrusted":
        envelope, evidence = signed_chains.observed_effect(
            dep, WF, permit.outcome_id, _now(), key=Ed25519PrivateKey.generate()
        )
    elif signer == "effect-key-as-achilles":
        # The effect key claiming to be the outcome key's engine: the keyring binds
        # each key to one engine, so the signature names the wrong observer.
        envelope, evidence = signed_chains.observed_effect(
            dep, WF, permit.outcome_id, _now(), engine="achilles", key=signed_chains.ENGINE_KEYS["achilles-effect"]
        )
    else:
        envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), engine=signer)

    resp = _send(service, dep, envelope, evidence)

    assert resp.status_code == 400, resp.content
    assert resp.json()["recorded"] == 0
    assert not WorkflowChainOutcome.objects.filter(effect_dispatch_id=evidence["dispatch_id"]).exists()


def test_one_key_is_never_two_kinds(engine_keyring, tmp_path):
    """The keyring refuses the observed-effect key filed under a second engine too,
    so an authorization check and an observed effect can never be one key."""
    key = signed_chains.ENGINE_KEYS["achilles-effect"]
    path = tmp_path / "keyring.json"
    raw = base64.b64encode(oc.raw_public_key(key)).decode()
    path.write_text(json.dumps([{"engine": "achilles-effect", "public_key": raw}, {"engine": "achilles", "public_key": raw}]))
    with pytest.raises(observed_outcomes.KeyringUnavailable, match="one key has one engine"):
        observed_outcomes.load_keyring(str(path))


def test_an_observed_effect_posted_as_a_plain_signed_outcome_is_refused(service):
    """Recorded with the document its digest names, or not at all: on the signed-
    outcome route it would be an observation bound to nothing."""
    from tests.test_spine_authority_chain import _admin, _client

    dep, _, permit, _ = _world()
    envelope, _evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    resp = _client(_admin()).post(_base(dep) + "chain-outcomes/observed/", envelope, format="json")
    assert resp.status_code == 400, resp.content
    assert "observed-effects route" in resp.json()["refused"][0]["reason"]


# -------------------------------------------------------------------- replay


def test_a_replayed_outcome_is_refused(service):
    dep, _, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(2))
    assert _send(service, dep, envelope, evidence).status_code == 201

    again = _send(service, dep, envelope, evidence)
    assert again.status_code == 400 and "already recorded" in again.json()["refused"][0]["reason"]

    # The same dispatch, observed "again" under a fresh outcome id: one observation
    # per dispatch, whatever id it carries.
    replay, replay_evidence = signed_chains.observed_effect(
        dep, WF, permit.outcome_id, _now(1), dispatch_id=evidence["dispatch_id"]
    )
    resp = _send(service, dep, replay, replay_evidence)
    assert resp.status_code == 400
    assert f"dispatch {evidence['dispatch_id']} was already observed" in resp.json()["refused"][0]["reason"]
    assert WorkflowChainOutcome.objects.filter(observer_engine="achilles-effect").count() == 1


def test_an_outcome_signed_for_another_deployment_is_refused(service):
    dep, _, permit, _ = _world()
    other, _, _, _ = _world()
    envelope, evidence = signed_chains.observed_effect(other, WF, permit.outcome_id, _now())
    resp = _send(service, dep, envelope, evidence)
    assert resp.status_code == 400 and "not this one" in resp.json()["refused"][0]["reason"]


# ----------------------------------------------- the evidence is what was signed


def test_evidence_that_is_not_the_signed_document_is_refused(service):
    dep, _, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    swapped = {**evidence, "tool": {"kind": "mcp_server", "identifier": "billing-mcp"}}
    resp = _send(service, dep, envelope, swapped)
    assert resp.status_code == 400 and "not the document the signature names" in resp.json()["refused"][0]["reason"]


def test_an_outcome_that_is_not_held_is_refused(service):
    dep, _, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(
        dep, WF, permit.outcome_id, _now(), status=oc.NOT_DEMONSTRATED
    )
    resp = _send(service, dep, envelope, evidence)
    assert resp.status_code == 400 and "signed held" in resp.json()["refused"][0]["reason"]


@pytest.mark.parametrize(
    "body",
    [{}, {"envelope": {}}, {"envelope": {}, "evidence": {}, "note": "x"}, {"envelope": {}, "evidence": {"schema": "x"}}],
    ids=["empty", "no-evidence", "extra-field", "not-the-schema"],
)
def test_a_body_that_cannot_be_read_is_refused(service, body):
    dep, _, _, _ = _world()
    resp = service.post(_base(dep) + "observed-effects/", body, format="json")
    assert resp.status_code == 400


def test_only_the_observed_effect_service_may_post(service):
    from tests.test_spine_authority_chain import _admin, _client

    dep, _, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now())
    payload = {"envelope": envelope, "evidence": evidence}
    admin = _client(_admin()).post(_base(dep) + "observed-effects/", payload, format="json")
    assert admin.status_code == 403
    anonymous = APIClient().post(_base(dep) + "observed-effects/", payload, format="json")
    assert anonymous.status_code == 401
    wrong = APIClient()
    wrong.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN="x" * 48)
    assert wrong.post(_base(dep) + "observed-effects/", payload, format="json").status_code == 401
    assert not WorkflowChainOutcome.objects.filter(observer_engine="achilles-effect").exists()


# ----------------------------------------- bound to the chain it is offered for


def _chain_citing(client, dep, permit, row, **kw):
    body = _chain_body(client, dep, permit, **kw)
    body["effect_outcome_id"] = row.outcome_id
    return _post(client, dep, body).json()["chains"][0]


@pytest.mark.parametrize(
    ("observed", "code"),
    [
        ({"tool": ("mcp_server", "billing-mcp")}, "effect_other_tool"),
        ({"tool": ("skill", "crm-mcp")}, "effect_other_tool"),
        ({"workflow": "other-workflow"}, "effect_outcome_other_workflow"),
        ({"gate": "another"}, "effect_other_dispatch"),
    ],
    ids=["another-tool", "another-kind", "another-workflow", "another-gate-decision"],
)
def test_an_observation_that_does_not_match_the_invokes_hop_does_not_prove_it(service, observed, code):
    dep, client, permit, _ = _world()
    gate = permit.outcome_id
    if observed.get("gate"):
        gate = signed_chains.record_signed(dep, WF, oc.HELD, _now(3)).outcome_id
    row = signed_chains.record_observed_effect(
        dep, observed.get("workflow", WF), gate, _now(), tool=observed.get("tool", ("mcp_server", "crm-mcp"))
    )
    chain = _chain_citing(client, dep, permit, row)
    produces = _hops(chain)["produces"]
    assert produces["verdict"] == "unproven"
    assert code in [r["code"] for r in produces["reasons"]]
    assert decision_support(_fresh(dep))["claim_cap"] == "needs_more_evidence"


def test_one_observation_cannot_prove_two_chains(service):
    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    first = _chain_citing(client, dep, permit, row)
    assert _hops(first)["produces"]["verdict"] == "proven"
    body = _chain_body(client, dep, permit)
    body["hops"][-1]["to"]["ref"] = "another-effect"
    body["effect_outcome_id"] = row.outcome_id
    _post(client, dep, body)
    chains = client.get(_base(dep) + "authority-chains/").json()["chains"]
    assert len([c for c in chains if c["standing"]]) == 2
    for c in chains:
        assert "effect_outcome_cited_twice" in [r["code"] for r in _hops(c)["produces"]["reasons"]]


def test_evidence_edited_after_it_was_recorded_proves_nothing(service):
    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    WorkflowChainOutcome.objects.filter(pk=row.pk).update(
        effect_evidence={**row.effect_evidence, "gate_outcome_id": "0" * 32}
    )
    chain = _chain_citing(client, dep, permit, row)
    assert [r["code"] for r in _hops(chain)["produces"]["reasons"]] == ["effect_evidence_unread"]


# ----------------------------------------------- the shared schema, by vectors


def _vectors():
    return json.loads(VECTORS.read_text())


def _envelope(hexed):
    """A vector's envelope as DSSE carries it: its hex fields, base64 again."""
    return {
        "payloadType": hexed["payloadType"],
        "payload": base64.b64encode(bytes.fromhex(hexed["payload_hex"])).decode(),
        "signatures": [
            {"keyid": s["keyid"], "sig": base64.b64encode(bytes.fromhex(s["sig_hex"])).decode()}
            for s in hexed["signatures"]
        ],
    }


def test_this_backend_verifies_the_conformance_vector_achilles_signed():
    """The same file Achilles signs byte for byte (its ``tests/vectors``): one schema,
    defined in each repository, held to one set of bytes. Nothing imports Achilles."""
    from assurance import observed_effects

    v = _vectors()
    seed = hashlib.sha256(v["effect_key_phrase"].encode()).digest()
    key = Ed25519PrivateKey.from_private_bytes(seed)
    raw = oc.raw_public_key(key)
    assert raw.hex() == v["effect_public_key_hex"]
    keyring = {oc.key_id_for(raw): oc.TrustedKey(raw, v["effect_engine"])}
    verdict = oc.verify_outcome(_envelope(v["envelope"]), keyring)
    assert verdict.verdict == oc.AUTHENTIC, verdict.reason
    assert observed_effects.examine(verdict.outcome, v["evidence"]) == ""
    assert oc.evidence_digest_of(v["evidence"]) == v["evidence_digest"] == verdict.outcome["evidence_digest"]
    assert comp.evidence_kind(comp.BASIS_DEMONSTRATED, verdict.outcome["observer"]["engine"]) == (
        comp.EVIDENCE_OBSERVED_EFFECT
    )
    # And the gate decision it is bound to is the one the vector's own gate signed.
    gate_raw = bytes.fromhex(v["gate_public_key_hex"])
    gate = oc.verify_outcome(
        _envelope(v["gate_envelope"]), {oc.key_id_for(gate_raw): oc.TrustedKey(gate_raw, "achilles")}
    )
    assert gate.outcome["outcome_id"] == v["evidence"]["gate_outcome_id"]


def test_every_invalid_vector_is_refused():
    from assurance import observed_effects

    v = _vectors()
    assert observed_effects.validate_evidence(v["evidence"]) == v["evidence"]
    assert observed_effects.TOOL_KINDS == __import__("assurance.authority_chain").authority_chain.TOOL_NODE_KINDS
    for case in v["invalid"]:
        with pytest.raises(observed_effects.EvidenceRefused):
            observed_effects.validate_evidence(case["evidence"])
