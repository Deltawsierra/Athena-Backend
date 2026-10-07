"""This exact authority chain produced this effect (SPINE, cross-cutting).

The roadmap item: grow the assurance graph from "these things are connected" to
"this exact authority chain produced this effect", and hold that for a
consequential effect every hop of the chain can be reconstructed and verified, any
unproven hop is named, a broken or unauthorized hop blocks READY, and the chain
appears in the receipt.

Measured on master (b7616d8) before this change: a deployment whose approved
workflow had a signed ``held`` and whose consequential effect ran through an
UNMANAGED MCP server read ``ready_restricted`` on an Achilles permit check and
``ready`` on an Athena scan -- and ``POST .../authority-chains/`` answered 404,
because nothing could record which authority produced the effect. Every test here
that posts a chain fails there.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import observed_outcomes
from assurance.decision import _worse, decision_support, recompute_decision
from assurance.models import Asset, Deployment, ServedRouteNote
from assurance.served_route import note_route
from tests.signed_chains import ENGINE_KEYS, record_signed, write_keyring

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

# What this change adds is imported where it is used, so on a tree without it these
# tests are collected and fail on what the deployment does -- a 404, a READY --
# rather than on an import.


def _chains_model():
    from assurance.models import AuthorityChain

    return AuthorityChain

User = get_user_model()
D = Deployment.Decision
WF = "support-update"
A = Asset.Classification


def _admin():
    return User.objects.create_user(username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN)


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _base(dep):
    return f"/api/assurance/deployments/{dep.uuid}/"


def _fresh(dep):
    return Deployment.objects.get(pk=dep.pk)


def _world(*, tool=A.APPROVED, identity="svc-x", gate=oc.HELD, engine="achilles", effect_class="write", bind=True):
    """The roadmap's example as a deployment: a support agent that invokes a CRM MCP
    server, acting as service account X, under an approved workflow that names the
    server; a gate decision Achilles signed for the workflow. The server declares
    that it writes (it updates customer records), so the workflow's effect through it
    is consequential and needs a chain (assurance.consequential)."""
    admin = _admin()
    client = _client(admin)
    dep = Deployment.objects.create(name=f"support{Deployment.objects.count()}", owner=admin)
    now = timezone.now()
    crm = {"permissions": ["customer:update", "customer:read"]}
    if effect_class is not None:
        crm["effect_class"] = effect_class
    for kind, name, classification, metadata in (
        ("agent", "support-agent", A.APPROVED, {"tools": ["crm-mcp"], "identity": identity}),
        ("mcp_server", "crm-mcp", tool, crm),
        ("service_account", "svc-x", A.APPROVED, {}),
        ("service_account", "svc-admin", A.APPROVED, {}),
    ):
        Asset.objects.create(
            deployment=dep, kind=kind, name=name, identifier=name, classification=classification,
            metadata=metadata, assessed_at=now,
        )
    # The served route as the platform noted it an hour ago, so what is observed now
    # was observed against it.
    note_route(dep, now=now - timedelta(hours=1))
    ServedRouteNote.objects.filter(deployment=dep).update(since=now - timedelta(hours=1))
    entry = {"slug": WF, "name": "Support update", "description": "update a customer record"}
    if bind:
        entry["tools"] = [{"kind": "mcp_server", "identifier": "crm-mcp"}]
    put = client.put(_base(dep) + "approved-workflows/", {"workflows": [entry]}, format="json")
    assert put.status_code == 200, put.content
    permit = record_signed(dep, WF, oc.HELD, datetime.now(dt_timezone.utc) - timedelta(minutes=2), engine=engine)
    refusal = None
    if gate != oc.HELD:
        refusal = record_signed(dep, WF, gate, datetime.now(dt_timezone.utc) - timedelta(minutes=10), engine="achilles")
    recompute_decision(_fresh(dep))
    return dep, client, permit, refusal


def _version(client, dep):
    return client.get(_base(dep) + "authority-chains/").json()["approvals_in_force"][WF]


def _hops(version, *, person=False, tool="crm-mcp", account="svc-x"):
    agent = {"kind": "agent", "ref": "support-agent"}
    policy = {"kind": "policy", "ref": WF, "version": version}
    mcp = {"kind": "mcp_server", "ref": tool}
    sa = {"kind": "service_account", "ref": account}
    action = {"kind": "action", "ref": "customer:update"}
    effect = {"kind": "effect", "ref": "customer-record-change"}
    head = []
    if person:
        user = {"kind": "user", "ref": "support-user"}
        head = [
            {"from": {"kind": "person", "ref": "employee"}, "relation": "authenticated_as", "to": user},
            {"from": user, "relation": "delegates_to", "to": agent},
        ]
    return [
        *head,
        {"from": agent, "relation": "under_policy", "to": policy},
        {"from": policy, "relation": "invokes", "to": mcp},
        {"from": mcp, "relation": "through_identity", "to": sa},
        {"from": sa, "relation": "performs", "to": action},
        {"from": action, "relation": "produces", "to": effect},
    ]


def _post(client, dep, body):
    return client.post(_base(dep) + "authority-chains/", body, format="json")


def _chain_body(client, dep, permit, **kw):
    return {
        "workflow": WF,
        "hops": _hops(_version(client, dep), **kw),
        "gate_outcome_id": permit.outcome_id,
        "observed_at": (timezone.now() - timedelta(minutes=1)).isoformat(),
        "source": "operator",
    }


def _by_relation(chain):
    return {h["relation"]: h for h in chain["hops"]}


# ---------------------------------------------------------------- the master probe


@pytest.mark.parametrize(
    ("engine", "before", "unproven"),
    [
        ("achilles", D.READY_RESTRICTED, [1, 2, 4]),
        # An Athena scan is no Action Gate decision: cited as one, the action is unproven too.
        ("athena", D.READY, [1, 2, 3, 4]),
    ],
)
def test_a_held_workflow_whose_effect_ran_through_a_shadow_node_no_longer_reads_ready(engine, before, unproven):
    dep, client, permit, _ = _world(tool=A.UNMANAGED, engine=engine)
    # The workflow chains alone still read what the deployment read on master...
    assert decision_support(_fresh(dep))["composition"]["signal"] == before
    # ...and since the owner's decision of 7 Oct the consequential effect no chain
    # names reads unproven before any chain is recorded (assurance.consequential).
    # On master this was `before`: recording the chain could only lower it.
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE
    (missing,) = decision_support(_fresh(dep))["claims"]["authority_chains_missing"]
    assert (missing["workflow"], missing["tool_kind"], missing["tool_identifier"]) == (WF, "mcp_server", "crm-mcp")

    answer = _post(client, dep, _chain_body(client, dep, permit))

    assert answer.status_code == 201, answer.content
    stored = _fresh(dep).decision
    assert stored == D.NEEDS_MORE_EVIDENCE
    assert _worse(before, stored) == stored, "a chain only ever moves the decision away from READY"
    chain = answer.json()["chains"][0]
    assert chain["verdict"] == "unproven" and chain["standing"]
    hops = _by_relation(chain)
    for relation in ("invokes", "through_identity"):
        assert hops[relation]["verdict"] == "unproven"
        assert "shadow_node" in {r["code"] for r in hops[relation]["reasons"]}
        assert any("crm-mcp" in r["detail"] and "unmanaged" in r["detail"] for r in hops[relation]["reasons"])
    assert chain["unproven_hops"] == unproven
    support = decision_support(_fresh(dep))
    assert support["decision"] == D.NEEDS_MORE_EVIDENCE
    held = support["claims"]["authority_chains_unproven"]
    assert [c["digest"] for c in held] == [chain["digest"]]
    assert support["claims"]["authority_chains_missing"] == [], "the chain recorded names the effect"
    assert "authority chain" in support["note"] and "crm-mcp" in support["note"]


# ------------------------------------------------------------- every hop, verified


def test_the_roadmap_chain_is_reconstructed_hop_by_hop_and_every_unproven_hop_is_named():
    dep, client, permit, _ = _world()
    answer = _post(client, dep, _chain_body(client, dep, permit, person=True))
    assert answer.status_code == 201, answer.content
    chain = answer.json()["chains"][0]

    assert [(h["from"]["kind"], h["relation"], h["to"]["kind"]) for h in chain["hops"]] == [
        ("person", "authenticated_as", "user"),
        ("user", "delegates_to", "agent"),
        ("agent", "under_policy", "policy"),
        ("policy", "invokes", "mcp_server"),
        ("mcp_server", "through_identity", "service_account"),
        ("service_account", "performs", "action"),
        ("action", "produces", "effect"),
    ]
    verdicts = {h["relation"]: (h["verdict"], {r["code"] for r in h["proven_by"] or h["reasons"]}) for h in chain["hops"]}
    assert verdicts == {
        # Part 4: a sign-in and a delegation have a signed record now, and none is
        # recorded here, so each hop names the record it lacks.
        "authenticated_as": ("unproven", {"no_authentication_record"}),
        "delegates_to": ("unproven", {"no_delegation_record"}),
        "under_policy": ("proven", {"approval_in_force"}),
        "invokes": ("proven", {"approved_contract_in_force", "declared_edge"}),
        "through_identity": ("proven", {"declared_identity"}),
        "performs": ("proven", {"declared_permission", "within_approval", "gate_permit"}),
        "produces": ("unproven", {"effect_not_observed"}),
    }
    assert chain["unproven_hops"] == [0, 1, 6] and chain["broken_hops"] == []
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE


def test_a_broken_hop_holds_the_decision_at_needs_remediation_and_the_note_names_it():
    # The agent acts as svc-admin, and the chain says the effect went through svc-x.
    dep, client, permit, _ = _world(identity="svc-admin")
    answer = _post(client, dep, _chain_body(client, dep, permit))
    assert answer.status_code == 201, answer.content
    chain = answer.json()["chains"][0]
    assert chain["verdict"] == "broken" and chain["broken_hops"] == [2]
    reasons = _by_relation(chain)["through_identity"]["reasons"]
    assert reasons[0]["code"] == "acts_as_another" and "svc-admin" in reasons[0]["detail"]

    assert _fresh(dep).decision == D.NEEDS_REMEDIATION
    support = decision_support(_fresh(dep))
    assert support["claim_cap"] == D.NEEDS_REMEDIATION
    assert [c["verdict"] for c in support["claims"]["authority_chains_broken"]] == ["broken"]
    assert support["note"].startswith("Held at 'needs remediation' by 1 authority chain(s)")
    assert "through_identity" in support["note"]


def test_an_action_the_gate_refused_breaks_the_chain_that_claims_it():
    dep, client, permit, refusal = _world(gate=oc.NOT_DEMONSTRATED)
    body = _chain_body(client, dep, permit)
    body["gate_outcome_id"] = refusal.outcome_id
    chain = _post(client, dep, body).json()["chains"][0]
    performs = _by_relation(chain)["performs"]
    assert performs["verdict"] == "broken"
    assert "gate_refused" in {r["code"] for r in performs["reasons"]}
    assert _fresh(dep).decision == D.NEEDS_REMEDIATION


def test_a_tool_outside_the_approval_is_unauthorized_and_blocks_ready():
    dep, client, permit, _ = _world()
    Asset.objects.create(
        deployment=dep, kind="mcp_server", name="billing-mcp", identifier="billing-mcp",
        classification=A.APPROVED, assessed_at=timezone.now(), metadata={"permissions": ["customer:update"]},
    )
    chain = _post(client, dep, _chain_body(client, dep, permit, tool="billing-mcp")).json()["chains"][0]
    invokes = _by_relation(chain)["invokes"]
    assert invokes["verdict"] == "broken"
    assert {"outside_approval", "unreachable"} <= {r["code"] for r in invokes["reasons"]}
    assert _fresh(dep).decision == D.NEEDS_REMEDIATION


def test_a_component_the_coverage_manifest_has_not_assessed_leaves_its_hops_unproven_until_it_is():
    dep, client, permit, _ = _world()
    Asset.objects.filter(deployment=dep, name="svc-x").update(assessed_at=None)
    chain = _post(client, dep, _chain_body(client, dep, permit)).json()["chains"][0]
    assert "unassessed_node" in {r["code"] for r in _by_relation(chain)["through_identity"]["reasons"]}

    # Read live: once something assesses it, that reason is gone without a rewrite.
    Asset.objects.filter(deployment=dep, name="svc-x").update(assessed_at=timezone.now())
    chain = _client(_admin()).get(_base(dep) + "authority-chains/").json()["chains"][0]
    assert chain["unproven_hops"] == [4], "only the effect nothing observed"


def test_an_approval_re_versioned_after_the_chain_leaves_the_policy_hop_unproven():
    dep, client, permit, _ = _world()
    old = _version(client, dep)
    _post(client, dep, _chain_body(client, dep, permit))
    client.put(
        _base(dep) + "approved-workflows/",
        {"workflows": [{"slug": WF, "name": "Support update", "description": "update any customer record",
                        "tools": [{"kind": "mcp_server", "identifier": "crm-mcp"}]}]},
        format="json",
    )
    read = client.get(_base(dep) + "authority-chains/").json()
    assert read["approvals_in_force"][WF] != old
    policy = _by_relation(read["chains"][0])["under_policy"]
    assert policy["verdict"] == "unproven"
    assert [r["code"] for r in policy["reasons"]] == ["policy_version_not_in_force"]


def test_a_route_that_moved_after_the_chain_leaves_the_invocation_unproven():
    dep, client, permit, _ = _world()
    _post(client, dep, _chain_body(client, dep, permit))
    Asset.objects.create(deployment=dep, kind="model", name="gpt-x", identifier="gpt-x",
                         classification=A.APPROVED, assessed_at=timezone.now(), metadata={"model_revision": "2"})
    chain = client.get(_base(dep) + "authority-chains/").json()["chains"][0]
    assert chain["route"] == "moved"
    assert "route_moved" in {r["code"] for r in _by_relation(chain)["invokes"]["reasons"]}


def test_a_workflow_whose_consequential_effect_has_no_chain_reads_unproven_not_todays_decision():
    # On master this read READY_RESTRICTED with no cap: an effect nobody recorded a
    # chain for was decided as if chains did not exist, so recording one could only
    # lower the decision. The owner's decision of 7 Oct: a missing chain reads
    # unproven, and the decision names the effect that lacks one.
    dep, client, _, _ = _world()
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_broken"] == support["claims"]["authority_chains_unproven"] == []
    assert support["claim_cap"] == D.NEEDS_MORE_EVIDENCE
    assert [(m["workflow"], m["tool_identifier"], m["status"]) for m in support["claims"]["authority_chains_missing"]] == [
        (WF, "crm-mcp", "missing")
    ]


# ---------------------------------------------------------- recording, superseding


def test_a_newer_chain_for_the_same_effect_supersedes_and_the_older_one_stays_published():
    dep, client, permit, refusal = _world(gate=oc.NOT_DEMONSTRATED)
    wrong = _chain_body(client, dep, permit)
    wrong["gate_outcome_id"] = refusal.outcome_id
    _post(client, dep, wrong)
    assert _fresh(dep).decision == D.NEEDS_REMEDIATION

    read = _post(client, dep, _chain_body(client, dep, permit)).json()
    assert read["recorded"] == 2 and read["standing"] == 1 and read["superseded"] == 1
    newest, oldest = read["chains"]
    assert (newest["standing"], newest["verdict"]) == (True, "unproven")
    assert (oldest["standing"], oldest["verdict"]) == (False, "broken")
    assert _fresh(dep).decision == D.NEEDS_MORE_EVIDENCE
    assert _chains_model().objects.filter(deployment=dep).count() == 2


def test_a_recorded_chain_is_never_rewritten_or_deleted():
    dep, client, permit, _ = _world()
    _post(client, dep, _chain_body(client, dep, permit))
    row = _chains_model().objects.get(deployment=dep)
    row.note = "edited"
    from assurance.models import AuthorityChainRewriteRefused

    with pytest.raises(AuthorityChainRewriteRefused):
        row.save()
    with pytest.raises(AuthorityChainRewriteRefused):
        row.delete()


@pytest.mark.parametrize(
    ("edit", "field"),
    [
        (lambda body: body["hops"].pop(2), "hops"),
        (lambda body: body.update(basis="demonstrated"), "basis"),
        (lambda body: body.update(workflow="not a slug"), "workflow"),
        (lambda body: body["hops"][0]["to"].update(ref="another-workflow"), "hops"),
    ],
)
def test_a_write_that_is_not_a_chain_is_refused_and_records_nothing(edit, field):
    dep, client, permit, _ = _world()
    before = _fresh(dep).decision
    body = _chain_body(client, dep, permit)
    edit(body)
    answer = _post(client, dep, body)
    assert answer.status_code == 400 and field in answer.json(), answer.content
    assert not _chains_model().objects.filter(deployment=dep).exists()
    # Unchanged by the refused write: the effect still has no chain, so it reads unproven.
    assert _fresh(dep).decision == before == D.NEEDS_MORE_EVIDENCE


def test_a_batch_is_recorded_whole_or_not_at_all_and_only_by_an_admin():
    dep, client, permit, _ = _world()
    good = _chain_body(client, dep, permit)
    bad = _chain_body(client, dep, permit)
    bad["hops"] = bad["hops"][:2]
    answer = _post(client, dep, {"chains": [good, bad]})
    assert answer.status_code == 400 and answer.json()[0] == {} and "produces" in json.dumps(answer.json()[1])
    assert not _chains_model().objects.filter(deployment=dep).exists()

    analyst = User.objects.create_user(username="analyst", password="x", role=User.Roles.ANALYST)
    assert _client(analyst).post(_base(dep) + "authority-chains/", good, format="json").status_code == 403
    assert _client(analyst).get(_base(dep) + "authority-chains/").status_code == 200
    assert not _chains_model().objects.filter(deployment=dep).exists()


# ----------------------------------------------------------------- signed chains


def _signed_envelope(dep, body, *, status=oc.HELD, digest=None, engine="athena"):
    from assurance import authority_chain as ac
    from assurance.authority_chain_records import chain_digest, chain_document

    hops, errors = ac.parse_hops(body["hops"], body["workflow"])
    assert not errors
    digest = digest or chain_digest(
        chain_document(str(dep.uuid), body["workflow"], hops, body.get("gate_outcome_id", ""), "")
    )
    outcome = oc.build_outcome(
        deployment=str(dep.uuid), workflow=body["workflow"], status=status, engine=engine,
        engine_version="1.0.0", run_id="run-chain", evidence_digest=digest,
        observed_at=datetime.now(dt_timezone.utc) - timedelta(minutes=1),
        reason="" if status == oc.HELD else "the chain did not hold",
    )
    return oc.sign_outcome(outcome, ENGINE_KEYS[engine])


def test_a_chain_an_engine_signed_is_demonstrated_while_the_signature_verifies(monkeypatch, tmp_path):
    dep, client, permit, _ = _world()
    body = _chain_body(client, dep, permit)
    body.pop("observed_at")
    body["envelope"] = _signed_envelope(dep, body)
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    chain = answer.json()["chains"][0]
    assert (chain["basis"], chain["basis_in_force"], chain["signed"]) == ("demonstrated", "demonstrated", True)
    assert chain["observer_engine"] == "athena"

    # Withdraw the athena key: the chain reads as what it then is, a person's record.
    ring = tmp_path / "only-achilles.json"
    write_keyring(ring, {"achilles": ENGINE_KEYS["achilles"]})
    monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(ring))
    chain = client.get(_base(dep) + "authority-chains/").json()["chains"][0]
    assert (chain["basis"], chain["basis_in_force"], chain["signed"]) == ("demonstrated", "attested", False)


@pytest.mark.parametrize(
    ("kw", "says"),
    [
        ({"digest": "sha256:" + "ee" * 32}, "covers another chain"),
        ({"status": oc.VIOLATED}, "chain-outcomes"),
    ],
)
def test_an_envelope_that_does_not_sign_exactly_this_chain_is_refused(kw, says):
    dep, client, permit, _ = _world()
    body = _chain_body(client, dep, permit)
    body.pop("observed_at")
    body["envelope"] = _signed_envelope(dep, body, **kw)
    answer = _post(client, dep, body)
    assert answer.status_code == 400 and says in json.dumps(answer.json()), answer.content
    assert not _chains_model().objects.filter(deployment=dep).exists()


# ---------------------------------------------------------- receipt and verifier


def test_the_chain_and_every_hops_verdict_appear_in_the_receipt_and_the_verifier_reads_them():
    from tests.test_receipt_spec_conformance import verifier

    dep, client, permit, _ = _world(tool=A.UNMANAGED)
    before = client.get(_base(dep) + "assurance-receipt/").json()
    assert before["receipt_version"] == "mythos.assurance.receipt/6.0"
    assert before["authority_chains"]["standing"] == 0 and before["authority_chains"]["chains"] == []

    chain = _post(client, dep, _chain_body(client, dep, permit)).json()["chains"][0]
    receipt = client.get(_base(dep) + "assurance-receipt/").json()
    section = receipt["authority_chains"]
    assert receipt["digest"] != before["digest"]
    assert section["verdict_census"] == {"broken": 0, "proven": 0, "unproven": 1}
    assert section["basis_census"] == {"attested": 1, "demonstrated": 0}
    (listed,) = section["chains"]
    assert listed["digest"] == chain["digest"] and listed["verdict"] == "unproven"
    assert [(h["relation"], h["verdict"]) for h in listed["hops"]] == [
        ("under_policy", "proven"), ("invokes", "unproven"), ("through_identity", "unproven"),
        ("performs", "proven"), ("produces", "unproven"),
    ]
    assert "shadow_node" in listed["hops"][1]["readings"]
    assert "crm-mcp" not in json.dumps(section), "the receipt names chains by digest, never by node"

    # The offline verifier reads the section: shape, and each chain as its worst hop.
    assert verifier._authority_chains(section) is None
    lines = verifier._authority_lines(receipt)
    assert lines[0] == "authority 1 chain(s) in force: 0 proven, 1 unproven, 0 broken"
    assert lines[1].startswith(f"chain     {chain['digest']} unproven (attested): hop 1 invokes unproven (")
    verdict = verifier.verify(json.dumps(receipt).encode())
    assert (verdict.verified, verdict.reason) == (False, "unsigned"), verdict.render()


# --------------------------------------------------------------------- the safety


def test_a_broken_chain_holds_no_stop():
    dep, client, permit, _ = _world(identity="svc-admin")
    _post(client, dep, _chain_body(client, dep, permit))
    assert _fresh(dep).decision == D.NEEDS_REMEDIATION
    paused = client.post(_base(dep) + "recompute/", {"paused": True}, format="json")
    assert paused.status_code == 200, paused.content
    assert _fresh(dep).decision == D.PAUSED
    assert decision_support(_fresh(dep))["decision"] == D.PAUSED
