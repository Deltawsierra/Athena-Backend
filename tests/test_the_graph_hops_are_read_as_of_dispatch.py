"""An authority chain's graph hops are read as of its dispatch (the follow-up to part 5).

On master (11366c8) ``under_policy`` and ``invokes``' approval, contract and route were
read as of dispatch, and ``through_identity``, ``performs`` and the reach half of
``invokes`` were still read LIVE from the graph, which kept no history. So:

* an identity, permission or reach edge changed after an effect unproved that effect;
* an effect made through an edge removed before its dispatch read proven once the edge
  was restored.

Now every edge those hops read is kept as an append-only history of when it came into
force and went out of it, as the platform noticed (``AuthorityEdgeVersion``), noted in
the transaction of every asset write and at every decision refresh, and the hops read
the edge in force at the effect's signed dispatch instant:

* an edge changed after the effect leaves it proven, citing the history row;
* an edge removed before the dispatch and restored after reads unproven, named;
* a dispatch the history does not cover reads unproven, never live;
* a person-started chain stays proven across a later re-approval and identity edit;
* nothing added stands on a stop's path.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from assurance import observed_effects
from assurance.decision import decision_support
from assurance.models import (
    Asset,
    AuthorityEdgeVersion,
    AuthorityEdgeVersionRewriteRefused,
    Deployment,
    WorkflowChainOutcome,
)
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


def _readings(chain):
    return {r: _codes(h) for r, h in _hops(chain).items()}


def _chain_citing(client, dep, permit, effect_row, **kw):
    body = _chain_body(client, dep, permit, **kw)
    body["effect_outcome_id"] = effect_row.outcome_id
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    return answer.json()["chains"][0]


def _asset(dep, name):
    return Asset.objects.get(deployment=dep, identifier=name)


def _edit(dep, name, **metadata):
    """An operator's edit of one component's declaration: a save, as every writer makes."""
    asset = _asset(dep, name)
    asset.metadata = {**asset.metadata, **metadata}
    asset.save()


def _edges(dep, kind):
    return [
        (r.source, r.target, r.in_force)
        for r in AuthorityEdgeVersion.objects.filter(deployment=dep, kind=kind).order_by("noticed_at", "id")
    ]


#: Each graph hop of the world's chain, the edit that takes its edge away, the edit that
#: restores it, and what the hop reads proven and unproven. The agent acts as svc-x and
#: reaches the CRM server, which declares that it updates customer records.
GRAPH_EDITS = [
    ("through_identity", ("support-agent", {"identity": "svc-admin"}), ("support-agent", {"identity": "svc-x"}),
     "identity_in_force_at_dispatch", "identity_not_in_force_at_dispatch"),
    ("invokes", ("support-agent", {"tools": []}), ("support-agent", {"tools": ["crm-mcp"]}),
     "reach_in_force_at_dispatch", "reach_not_in_force_at_dispatch"),
    ("performs", ("crm-mcp", {"permissions": ["customer:read"]}), ("crm-mcp", {"permissions": ["customer:update", "customer:read"]}),
     "action_in_force_at_dispatch", "action_not_in_force_at_dispatch"),
]
IDS = [edit[0] for edit in GRAPH_EDITS]


# ------------------------------------------------------ changed after the effect


@pytest.mark.parametrize(("relation", "remove", "restore", "proven", "unproven"), GRAPH_EDITS, ids=IDS)
def test_an_edge_changed_after_the_effect_leaves_the_chain_proven(relation, remove, restore, proven, unproven):
    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    chain = _chain_citing(client, dep, permit, row)
    assert chain["verdict"] == "proven", _readings(chain)

    _edit(dep, remove[0], **remove[1])

    chain = _chains(client, dep)[0]
    assert chain["verdict"] == "proven", _readings(chain)
    hop = _hops(chain)[relation]
    cited = next(r for r in hop["proven_by"] if r["code"] == proven)["detail"]
    # It cites the history row that put the edge in force, an hour before the dispatch.
    assert "edge history row" in cited
    assert decision_support(_fresh(dep))["claims"]["authority_chains_unproven"] == []


def test_an_identity_edit_after_the_effect_is_in_the_history_and_moves_nothing():
    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    _chain_citing(client, dep, permit, row)
    lifted = _fresh(dep).decision
    agent, svc_x, svc_admin = (str(_asset(dep, n).uuid) for n in ("support-agent", "svc-x", "svc-admin"))

    _edit(dep, "support-agent", identity="svc-admin")

    # The history says the agent stopped acting as svc-x and began acting as svc-admin,
    # noticed in the edit's own transaction; the chain still reads the dispatch.
    assert set(_edges(dep, "identity")[-2:]) == {(agent, svc_admin, True), (agent, svc_x, False)}
    chain = _chains(client, dep)[0]
    assert _codes(_hops(chain)["through_identity"]) == ["identity_in_force_at_dispatch"]
    assert "svc-x" in _hops(chain)["through_identity"]["proven_by"][0]["detail"]
    assert _fresh(dep).decision == lifted


# --------------------------------------------- removed before, restored after


@pytest.mark.parametrize(("relation", "remove", "restore", "proven", "unproven"), GRAPH_EDITS, ids=IDS)
def test_an_edge_removed_before_the_dispatch_and_restored_after_reads_unproven(relation, remove, restore, proven, unproven):
    dep, client, permit, _ = _world()
    _edit(dep, remove[0], **remove[1])
    # Dispatched with the edge out of force, presenting the approval as it stands.
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    _edit(dep, restore[0], **restore[1])

    # Live, the graph holds the edge again; at the dispatch it did not.
    chain = _chain_citing(client, dep, permit, row)
    hop = _hops(chain)[relation]
    assert hop["verdict"] == "unproven", hop
    assert unproven in _codes(hop) and proven not in _codes(hop)
    assert chain["verdict"] == "unproven" and chain["broken_hops"] == []
    support = decision_support(_fresh(dep))
    assert [c["digest"] for c in support["claims"]["authority_chains_unproven"]] == [chain["digest"]]
    assert _fresh(dep).decision == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_the_identity_the_agent_acted_as_at_the_dispatch_is_named():
    dep, client, permit, _ = _world()
    _edit(dep, "support-agent", identity="svc-admin")
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    _edit(dep, "support-agent", identity="svc-x")
    hop = _hops(_chain_citing(client, dep, permit, row))["through_identity"]
    assert _codes(hop) == ["identity_not_in_force_at_dispatch"]
    assert "it acted as svc-admin then" in hop["reasons"][0]["detail"]


# ------------------------------------------------------------- a missing record


def test_a_dispatch_before_the_edge_history_began_reads_unrecorded_never_live():
    dep, client, permit, _ = _world()
    # The approval, contracts and route were noted an hour ago; the graph's edges only
    # now. A dispatch half a minute ago is one whose edges nothing records.
    AuthorityEdgeVersion.objects.filter(deployment=dep).update(noticed_at=_now())
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now() - timedelta(seconds=30))
    chain = _chain_citing(client, dep, permit, row)
    hops = _hops(chain)
    assert _codes(hops["under_policy"]) == ["approval_in_force_at_dispatch"], "the approval history covers it"
    for relation in ("invokes", "through_identity", "performs"):
        hop = hops[relation]
        assert hop["verdict"] == "unproven", relation
        assert any(
            r["code"] == "dispatch_state_unrecorded" and "graph's edges" in r["detail"] for r in hop["reasons"]
        ), relation
    assert chain["verdict"] == "unproven"


def test_a_v1_observed_effect_leaves_the_graph_hops_unrecorded(service):
    dep, client, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), schema="v1")
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    hops = _hops(_chain_citing(client, dep, permit, row))
    assert _codes(hops["produces"]) == ["observed_effect"]
    assert _codes(hops["through_identity"]) == ["dispatch_state_unrecorded"]
    assert "dispatch_state_unrecorded" in _codes(hops["performs"])


# ------------------------------------------------- the person hops, end to end


def test_a_person_started_chain_stays_proven_across_a_later_re_approval_and_identity_edit(collectors, service):
    dep, client, permit, _ = _world()
    effect_at = _now()
    sign_in = _sign_in(dep, effect_at)
    grant = _grant(dep, effect_at)
    assert _send_identity(collectors["authentication"], dep, "authentication", *sign_in).status_code == 201
    assert _send_identity(collectors["delegation"], dep, "delegation", *grant).status_code == 201
    presented = signed_chains.live_presented(
        dep, WF, assertion=sign_in[1]["assertion_digest"], grant=grant[1]["grant_digest"]
    )
    envelope, evidence = signed_chains.observed_effect(dep, WF, permit.outcome_id, effect_at, presented=presented)
    assert _send(service, dep, envelope, evidence).status_code == 201
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    chain = _person_chain(client, dep, permit, row)
    assert chain["verdict"] == "proven", _readings(chain)

    # A re-approval after the effect...
    put = client.put(
        _base(dep) + "approved-workflows/",
        {"workflows": [{"slug": WF, "name": "Support update", "description": "update any customer record",
                        "tools": [{"kind": "mcp_server", "identifier": "crm-mcp"}]}]},
        format="json",
    )
    assert put.status_code == 200, put.content
    # ...and an identity edit after it: the agent acts as svc-admin now.
    _edit(dep, "support-agent", identity="svc-admin")

    chain = _chains(client, dep)[0]
    assert chain["verdict"] == "proven", _readings(chain)
    assert _readings(chain) == {
        "authenticated_as": ["authentication"],
        "delegates_to": ["delegation"],
        "under_policy": ["approval_in_force_at_dispatch"],
        "invokes": ["contract_in_force_at_dispatch", "route_at_dispatch", "reach_in_force_at_dispatch"],
        "through_identity": ["identity_in_force_at_dispatch"],
        "performs": ["action_in_force_at_dispatch", "within_approval_at_dispatch", "gate_permit"],
        "produces": ["observed_effect"],
    }
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_unproven"] == support["claims"]["authority_chains_missing"] == []
    assert support["claim_cap"] is None


# ----------------------------------------------------------------- the history


def test_every_asset_write_appends_the_edges_it_moves_and_the_history_is_append_only():
    dep, _, _, _ = _world()
    assert AuthorityEdgeVersion.objects.filter(deployment=dep, kind="begun").count() == 1
    agent, crm = str(_asset(dep, "support-agent").uuid), str(_asset(dep, "crm-mcp").uuid)
    before = AuthorityEdgeVersion.objects.filter(deployment=dep).count()

    # A created component's declarations come into force with it...
    new = Asset.objects.create(deployment=dep, kind="tool", name="lookup", identifier="lookup",
                               metadata={"permissions": ["customer:read"]})
    assert (str(new.uuid), "customer:read", True) in _edges(dep, "action")
    # ...an edit moves them...
    _edit(dep, "support-agent", tools=["crm-mcp", "lookup"])
    assert (agent, str(new.uuid), True) in _edges(dep, "reach")
    # ...a save that changes nothing the graph reads appends nothing...
    count = AuthorityEdgeVersion.objects.filter(deployment=dep).count()
    _asset(dep, "crm-mcp").save()
    stamp = _asset(dep, "crm-mcp")
    stamp.assessed_at = _now()
    stamp.save(update_fields=["assessed_at"])
    assert AuthorityEdgeVersion.objects.filter(deployment=dep).count() == count
    # ...and a deleted one takes its edges out of force.
    _asset(dep, "lookup").delete()
    assert (agent, str(new.uuid), False) in _edges(dep, "reach")
    assert (str(new.uuid), "customer:read", False) in _edges(dep, "action")
    assert AuthorityEdgeVersion.objects.filter(deployment=dep).count() > before
    assert (crm, "customer:update", True) in _edges(dep, "action")

    first = AuthorityEdgeVersion.objects.filter(deployment=dep).order_by("id").first()
    with pytest.raises(AuthorityEdgeVersionRewriteRefused):
        first.save()
    with pytest.raises(AuthorityEdgeVersionRewriteRefused):
        first.delete()


def test_a_scan_that_declares_an_agent_notes_its_edges_once_in_its_own_transaction():
    from assurance.assets import derive_assets
    from pentest.models import PentestScan

    admin = User.objects.create_user(username="scan-owner", password="x")
    dep = Deployment.objects.create(name="declared", owner=admin)
    scan = PentestScan.objects.create(
        user=admin, target_url="https://app.example.com/", consent=True, status=PentestScan.STATUS_COMPLETED,
        target_config={
            "agent": {"name": "assistant", "identifier": "assistant"},
            "tools": [{"name": "reader", "identifier": "reader", "permissions": ["read"]}],
        },
    )
    derive_assets(dep, scan)
    agent = Asset.objects.get(deployment=dep, kind="agent")
    reader = Asset.objects.get(deployment=dep, identifier="reader")
    rows = list(AuthorityEdgeVersion.objects.filter(deployment=dep))
    assert {(r.kind, r.source, r.target, r.in_force) for r in rows} == {
        ("begun", "", "", True),
        ("reach", str(agent.uuid), str(reader.uuid), True),
        ("action", str(reader.uuid), "read", True),
    }
    # Noted once, when the reconciliation was done: no half-reconciled graph between.
    assert len({r.noticed_at for r in rows}) == 1


def test_an_edge_no_signal_saw_is_noted_by_the_next_decision_refresh():
    from assurance.decision import refresh_stored_decisions

    dep, _, _, _ = _world()
    # A bulk update, which sends no signal: the CRM server stops declaring the update.
    Asset.objects.filter(deployment=dep, identifier="crm-mcp").update(metadata={"permissions": ["customer:read"]})
    crm = str(_asset(dep, "crm-mcp").uuid)
    assert (crm, "customer:update", False) not in _edges(dep, "action")
    refresh_stored_decisions([dep.pk])
    assert (crm, "customer:update", False) in _edges(dep, "action")


def test_an_asset_moved_to_another_deployment_moves_its_edges_out_of_the_one_it_left():
    dep, _, _, _ = _world()
    other = Deployment.objects.create(name="elsewhere", owner=dep.owner)
    crm = _asset(dep, "crm-mcp")
    crm.deployment = other
    crm.save(update_fields=["deployment"])
    assert (str(crm.uuid), "customer:update", False) in _edges(dep, "action")
    assert (str(crm.uuid), "customer:update", True) in _edges(other, "action")


# ------------------------------------------------------------------- the safety


def test_a_pause_reads_and_writes_no_edge_history_calls_recompute_only_and_still_wins(monkeypatch):
    """The safety rule: nothing added sits on a stop's path. A pause is
    ``recompute_decision`` and nothing else -- not the refresh that notes the edges --
    and it reads and writes no edge history: with every edge-history function made to
    fail, it still lands."""
    from assurance import decision, edge_history, views

    dep, client, permit, _ = _world()
    row = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, _now())
    _chain_citing(client, dep, permit, row)

    def refuse(*args, **kwargs):
        raise AssertionError("a pause touched the edge history")

    for name in ("note_edges", "note_edges_quietly", "edges_now", "history"):
        monkeypatch.setattr(edge_history, name, refuse)
    refreshed = []
    monkeypatch.setattr(decision, "refresh_stored_decisions", lambda ids: refreshed.append(list(ids)))
    recomputed = []
    real = views.recompute_decision

    def recompute(deployment, *args, **kwargs):
        recomputed.append(kwargs.get("paused"))
        return real(deployment, *args, **kwargs)

    monkeypatch.setattr(views, "recompute_decision", recompute)

    with CaptureQueriesContext(connection) as captured:
        paused = client.post(_base(dep) + "recompute/", {"paused": True}, format="json")
    assert paused.status_code == 200, paused.content
    assert _fresh(dep).decision == Deployment.Decision.PAUSED
    assert recomputed == [True], "a pause is recompute_decision, once"
    assert refreshed == [], "a pause does not run the refresh that notes the edges"
    touched = [q["sql"] for q in captured if "authorityedgeversion" in q["sql"].lower()]
    assert touched == [], "a pause waits on no edge history"


def test_no_stop_route_writes_an_asset():
    """The edge history is noted on asset writes; none of the stop routes is one."""
    from safety import stops

    assert "asset-list" not in stops.STOP_ROUTES and "asset-detail" not in stops.STOP_ROUTES
    assert set(stops.NOT_STOPS["asset-list"]) == set(stops.NOT_STOPS["asset-detail"]) == {"GET"}
