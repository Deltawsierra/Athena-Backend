"""A missing authority chain reads unproven (SPINE, the owner's decision of 7 Oct).

#133 recorded and verified authority chains, and an effect with NO recorded chain
kept the decision it had before chains existed. So recording a chain could only lower
a decision: the incentive was not to record one. Measured on master (0679a6c): the
roadmap's deployment -- a support agent whose approved workflow binds a CRM MCP server
that declares it writes -- read ``ready_restricted`` with no chain recorded, and
``needs_more_evidence`` the moment someone recorded the chain it ran through.

Now "consequential" is computed from data (:mod:`assurance.consequential`): an effect
an approved workflow has through a tool whose contract declares a write or destructive
effect class needs a chain, and with none in force it reads unproven and the decision
names it. A tool that declares no effect class reads unknown, and unproven, with its
own reason. A read-only one needs no chain. A chain whose every hop is proven lifts it.

Every test here fails on master: the decision there is not held, and nothing there
names an effect.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from mythos_core import outcome as oc

from assurance import composition as comp
from assurance.decision import decision_support
from assurance.models import Asset, Deployment
from assurance.revalidation import plan_revalidation
from tests import signed_chains
from tests.test_spine_authority_chain import WF, _base, _chain_body, _client, _fresh, _post, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

D = Deployment.Decision
A = Asset.Classification


def _effects(client, dep):
    return {e["tool_identifier"]: e for e in client.get(_base(dep) + "authority-chains/").json()["effects"]}


# ------------------------------------------------- a consequential effect, no chain


def test_a_consequential_effect_with_no_chain_reads_unproven_and_the_decision_names_it():
    dep, client, _, _ = _world()
    # The workflow chains alone read what master read: the gate authorized the action.
    support = decision_support(_fresh(dep))
    assert support["composition"]["signal"] == D.READY_RESTRICTED
    # And the write through crm-mcp, which no chain names, holds it at needs more evidence.
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE
    assert support["decision"] == support["claim_cap"] == D.NEEDS_MORE_EVIDENCE
    (missing,) = support["claims"]["authority_chains_missing"]
    assert missing["workflow"] == WF
    assert (missing["tool_kind"], missing["tool_identifier"]) == ("mcp_server", "crm-mcp")
    assert (missing["effect_class"], missing["class"], missing["status"]) == ("write", "consequential", "missing")
    assert missing["reasons"] == ["declared_write", "no_chain_in_force"]
    assert missing["digest"].startswith("sha256:")
    # It says exactly what to record.
    assert WF in missing["to_do"] and "invokes hop names mcp_server 'crm-mcp'" in missing["to_do"]
    assert support["note"].startswith("Held at 'needs more evidence' by 1 consequential effect(s)")
    assert "'crm-mcp'" in support["note"]
    assert support["claims"]["effect_classes_unknown"] == []

    # The plan names it as work, and never says nothing needs doing.
    plan = plan_revalidation(_fresh(dep))
    assert [e["digest"] for e in plan["authority_chains_to_record"]] == [missing["digest"]]
    assert plan["summary"]["authority_chains_to_record"] == 1
    assert "record the chain" in plan["note"] and "Nothing needs to be re-run" not in plan["note"]

    # The authority-chains route serves it, named, beside its digest.
    effect = _effects(client, dep)["crm-mcp"]
    assert (effect["digest"], effect["status"]) == (missing["digest"], "missing")


def test_recording_the_chain_names_the_effect_and_its_unproven_hops_hold_it_instead():
    dep, client, permit, _ = _world()
    chain = _post(client, dep, _chain_body(client, dep, permit)).json()["chains"][0]
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_missing"] == []
    assert [c["digest"] for c in support["claims"]["authority_chains_unproven"]] == [chain["digest"]]
    effect = _effects(client, dep)["crm-mcp"]
    assert (effect["status"], effect["chains"]) == ("covered", [chain["digest"]])
    # Recording the chain no longer lowers anything: the decision stays where the
    # missing chain had put it.
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE


# --------------------------------------------- a fully proven chain lifts the effect


@pytest.fixture
def collector(engine_keyring, monkeypatch):
    """An independent collector whose signed outcomes read as ``observed_effect``.
    NOTHING in production is one (``assurance.composition.SIGNER_EVIDENCE`` maps no
    signer to it, and a test pins that); here a key is trusted as one, so the
    ``produces`` hop -- the one hop no production data can prove today -- can be."""
    monkeypatch.setitem(signed_chains.ENGINE_KEYS, "collector", Ed25519PrivateKey.generate())
    signed_chains.write_keyring(engine_keyring)
    monkeypatch.setitem(comp.SIGNER_EVIDENCE, "collector", comp.EVIDENCE_OBSERVED_EFFECT)
    return "collector"


def test_a_chain_whose_every_hop_is_proven_lifts_the_missing_chain(collector):
    dep, client, permit, _ = _world()
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE

    observed = signed_chains.record_signed(
        dep, WF, oc.HELD, datetime.now(dt_timezone.utc) - timedelta(minutes=1), engine=collector
    )
    # Starting at the agent: sign-in and delegation (authenticated_as, delegates_to)
    # have no record anywhere in this platform, so a chain naming them cannot be proven.
    body = _chain_body(client, dep, permit)
    body["effect_outcome_id"] = observed.outcome_id
    chain = _post(client, dep, body).json()["chains"][0]

    assert chain["verdict"] == "proven", [h["reasons"] for h in chain["hops"] if h["verdict"] != "proven"]
    assert {h["relation"]: [r["code"] for r in h["proven_by"]] for h in chain["hops"]}["produces"] == [
        "observed_effect"
    ]
    support = decision_support(_fresh(dep))
    claims = support["claims"]
    assert claims["authority_chains_missing"] == claims["authority_chains_unproven"] == []
    assert claims["authority_chains_broken"] == [] and support["claim_cap"] is None
    assert _effects(client, dep)["crm-mcp"]["status"] == "covered"
    # Lifted: the decision is the workflow chains' again, no longer held by authority.
    assert _fresh(dep).decision == support["decision"] == support["composition"]["signal"]
    assert _fresh(dep).decision in (D.READY, D.READY_RESTRICTED)


# --------------------------------------------------------- undeclared and read-only


@pytest.mark.parametrize(
    ("effect_class", "code"),
    [(None, "effect_class_undeclared"), ("sideways", "effect_class_unrecognised")],
)
def test_a_tool_whose_effect_class_is_undeclared_reads_unknown_and_unproven(effect_class, code):
    dep, client, permit, _ = _world(effect_class=effect_class)
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_missing"] == []
    (unknown,) = support["claims"]["effect_classes_unknown"]
    assert (unknown["tool_identifier"], unknown["class"], unknown["status"]) == ("crm-mcp", "unknown", "unknown")
    assert unknown["reasons"] == [code]
    assert "declare the effect class" in unknown["to_do"]
    assert "effect class is unknown" in support["note"]
    assert plan_revalidation(_fresh(dep))["summary"]["effect_classes_to_declare"] == 1

    # A chain names who produced the effect, not what kind of effect it is: still unknown.
    _post(client, dep, _chain_body(client, dep, permit))
    support = decision_support(_fresh(dep))
    assert [u["status"] for u in support["claims"]["effect_classes_unknown"]] == ["unknown"]
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE


def test_a_read_only_effect_needs_no_chain():
    dep, client, _, _ = _world(effect_class="read")
    effect = _effects(client, dep)["crm-mcp"]
    assert (effect["class"], effect["status"], effect["to_do"]) == ("read_only", "not_required", None)
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_missing"] == support["claims"]["effect_classes_unknown"] == []
    assert support["claim_cap"] is None
    # What master read for this deployment, unchanged: only the gate's permit check restricts it.
    assert _fresh(dep).decision == D.READY_RESTRICTED


# ------------------------------------------------------------------ the receipt


def test_the_receipt_carries_the_missing_effect_by_digest_and_the_verifier_names_it():
    from tests.test_receipt_spec_conformance import verifier

    dep, client, _, _ = _world()
    receipt = client.get(_base(dep) + "assurance-receipt/").json()
    assert receipt["receipt_version"] == "mythos.assurance.receipt/6.0"
    section = receipt["consequential_effects"]
    assert section["status_census"] == {"covered": 0, "missing": 1, "not_required": 0, "unknown": 0}
    (listed,) = section["effects"]
    assert listed == {
        "digest": _effects(client, dep)["crm-mcp"]["digest"],
        "tool_kind": "mcp_server",
        "class": "consequential",
        "status": "missing",
        "readings": ["declared_write", "no_chain_in_force"],
        "chains": [],
    }
    assert "crm-mcp" not in json.dumps(section) and WF not in json.dumps(section), "named by digest only"

    assert verifier._consequential_effects(section, receipt["authority_chains"]) is None
    lines = verifier._effect_lines(receipt)
    assert lines[0] == "effects   1 approved: 0 covered, 1 missing a chain, 0 of an unknown class, 0 read-only"
    assert lines[1] == f"effect    {listed['digest']} missing (mcp_server, declared_write, no_chain_in_force)"
    verdict = verifier.verify(json.dumps(receipt).encode())
    assert (verdict.verified, verdict.reason) == (False, "unsigned"), verdict.render()


# --------------------------------------------------------------------- the safety


def test_a_pause_still_wins_over_a_missing_chain():
    dep, client, _, _ = _world()
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE
    paused = client.post(_base(dep) + "recompute/", {"paused": True}, format="json")
    assert paused.status_code == 200, paused.content
    assert _fresh(dep).decision == D.PAUSED
    support = decision_support(_fresh(dep))
    assert support["decision"] == D.PAUSED
    assert support["note"].startswith("Operator failsafe is paused")
    # The missing chain is still reported: paused is not the same as covered.
    assert [m["tool_identifier"] for m in support["claims"]["authority_chains_missing"]] == ["crm-mcp"]


def test_an_analyst_reads_the_effects_and_a_read_writes_nothing():
    dep, _, _, _ = _world()
    analyst = get_user_model().objects.create_user(username="analyst-e", password="x", role="analyst")
    before = _fresh(dep).decision
    read = _client(analyst).get(_base(dep) + "authority-chains/")
    assert read.status_code == 200
    assert [e["status"] for e in read.json()["effects"]] == ["missing"]
    assert read.json()["effect_census"] == {"covered": 0, "missing": 1, "not_required": 0, "unknown": 0}
    assert _fresh(dep).decision == before
