"""The gate verifies the tool contract it dispatches under (G6, athena-backend half).

Until now Achilles signed the tool contract digests a dispatch was PRESENTED under
(``mythos.observed-effect/v2``'s ``dispatch.presented.contracts``) and verified none of
them, and it never learnt which tools the approval it read in force covers. G6 closes
that, and this backend's half is three things (``G6-SPEC.md`` sections 1, 4 and 5):

* the approval-in-force route serves the approval's tools on ``?include=tools`` -- each
  tool binding with its contract digest, sorted, exactly the set the digest was taken
  over, read in the same transaction, with the history-level check covering both --
  refuses any other ``include`` (400, ``unknown_include``), and answers byte for byte as
  before without it;
* ``mythos.observed-effect/v4`` is accepted: v3 with ``dispatch.verified`` holding
  exactly four fields, ``tool_contract`` and ``approval_recipients`` (no nonces) beside
  v3's two, under the same DSSE signature; v1 to v3 read exactly as before;
* the ``invokes`` hop reads ``tool_contract`` as GATE-ATTESTED against the binding of
  the approval version the gate read, as of ``dispatched_at`` -- equal is proven
  (``contract_attested_in_force_at_dispatch``), a mismatch is broken
  (``contract_digest_contradicts_gate``) and never attested -- and the effect's read
  serves its ``approval_recipients``.

On master the route ignores ``include``, a v4 document is refused and the rule has no
gate-attested tool hop, so these fail there.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance import authority_chain as rule
from assurance import gate_approval, observed_effects
from assurance.authority_chain_records import approval_digest, dispatch_state
from assurance.models import (
    ApprovalVersion,
    ApprovedWorkflow,
    Asset,
    Deployment,
    ToolContract,
    ToolContractBinding,
    WorkflowChainOutcome,
)
from tests import signed_chains
from tests.test_an_observed_effect_proves_the_produces_hop import TOKEN, _send
from tests.test_spine_authority_chain import WF, _base, _fresh, _world
from tests.test_the_gate_attests_the_approval_it_read import READ_TOKEN, _chain, _reading, _reapprove, _record

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
CRM = ("mcp_server", "crm-mcp")
FOUR = {"approvals_digest", "workflow_approval", "tool_contract", "approval_recipients"}
BOUND = {
    "obligation": "two-person-refund",
    "approval": "sha256:" + "9a" * 32,
    "recipient": "bound",
    "destination": "acct-42",
    "tenant": "tenant-a",
}
LEGACY = {
    "obligation": "manager-sign-off",
    "approval": "sha256:" + "8b" * 32,
    "recipient": "unbound",
    "destination": None,
    "tenant": None,
}


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


def _stamp(instant):
    return instant.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _url(dep, query=""):
    return _base(dep) + f"workflows/{WF}/approval-in-force/" + query


def _latest(dep):
    return ApprovalVersion.objects.filter(deployment=dep, workflow=WF).order_by("in_force_from", "id").last()


def _live_bindings(dep):
    return list(
        ToolContractBinding.objects.filter(deployment=dep, workflow__slug=WF, released_at__isnull=True).order_by("pk")
    )


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _readings(hop):
    return hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"]


def _codes(hop):
    return [r["code"] for r in _readings(hop)]


def _recontract(client, dep, description="the CRM server may delete now"):
    """The CRM server's contract moves (it declares another permission) and the workflow
    is re-approved under the new one: a new contract digest, and a new approval version
    binding it. Returns the new contract digest."""
    crm = Asset.objects.get(deployment=dep, kind="mcp_server", identifier="crm-mcp")
    crm.metadata = {**crm.metadata, "permissions": ["customer:update", "customer:read", "customer:delete"]}
    crm.save()
    _reapprove(client, dep, description)
    (binding,) = _live_bindings(dep)
    return binding.contract_digest


# ------------------------------------------------------------- the route, with tools


def test_without_include_the_answer_is_byte_for_byte_what_it_was(gate):
    dep, _client, _permit, _ = _world()
    latest = _latest(dep)

    answer = gate.get(_url(dep))

    assert answer.status_code == 200, answer.content
    expected = {
        "deployment": str(dep.uuid),
        "workflow": WF,
        "version": str(latest.id),
        "digest": latest.digest,
        "in_force_from": _stamp(latest.in_force_from),
    }
    # The exact bytes an engine at today's Achilles reads: no tools, nothing reordered.
    assert answer.content == json.dumps(expected, separators=(",", ":")).encode()
    assert answer["Content-Type"] == "application/json"


def test_include_tools_answers_the_tools_the_digest_was_taken_over_sorted(gate):
    dep, client, _permit, _ = _world()
    for kind, name in (("tool", "zeta-tool"), ("mcp_server", "alpha-mcp"), ("skill", "b-skill")):
        Asset.objects.create(
            deployment=dep, kind=kind, name=name, identifier=name, classification=Asset.Classification.APPROVED,
            metadata={"permissions": ["customer:read"], "effect_class": "read"}, assessed_at=_now(),
        )
    # Approved in an order that is neither sorted by identifier nor by kind.
    put = client.put(
        _base(dep) + "approved-workflows/",
        {"workflows": [{"slug": WF, "name": "Support update", "description": "update a customer record", "tools": [
            {"kind": "tool", "identifier": "zeta-tool"},
            {"kind": "mcp_server", "identifier": "crm-mcp"},
            {"kind": "skill", "identifier": "b-skill"},
            {"kind": "mcp_server", "identifier": "alpha-mcp"},
        ]}]},
        format="json",
    )
    assert put.status_code == 200, put.content
    before = (ApprovalVersion.objects.count(), ToolContract.objects.count(), ToolContractBinding.objects.count())

    answer = gate.get(_url(dep, "?include=tools"))

    assert answer.status_code == 200, answer.content
    body = answer.json()
    latest = _latest(dep)
    bindings = {(b.tool_kind, b.tool_identifier): b.contract_digest for b in _live_bindings(dep)}
    assert list(body) == ["deployment", "workflow", "version", "digest", "in_force_from", "tools"]
    assert body["tools"] == [
        {"kind": "mcp_server", "identifier": "alpha-mcp", "digest": bindings[("mcp_server", "alpha-mcp")]},
        {"kind": "mcp_server", "identifier": "crm-mcp", "digest": bindings[("mcp_server", "crm-mcp")]},
        {"kind": "skill", "identifier": "b-skill", "digest": bindings[("skill", "b-skill")]},
        {"kind": "tool", "identifier": "zeta-tool", "digest": bindings[("tool", "zeta-tool")]},
    ]
    # The rest is exactly the answer without include.
    assert {k: v for k, v in body.items() if k != "tools"} == gate.get(_url(dep)).json()
    assert body["version"] == str(latest.id) and body["digest"] == latest.digest
    # Exactly the set the digest was taken over: the digest re-taken over the tools
    # served is the digest served, and the version's row records those very tools.
    workflow = ApprovedWorkflow.objects.get(deployment=dep, slug=WF)
    served = [SimpleNamespace(tool_kind=t["kind"], tool_identifier=t["identifier"], contract_digest=t["digest"])
              for t in body["tools"]]
    assert approval_digest(workflow, served) == body["digest"]
    assert latest.tools == [[t["kind"], t["identifier"], t["digest"]] for t in body["tools"]]
    # A read: nothing written.
    assert (ApprovalVersion.objects.count(), ToolContract.objects.count(), ToolContractBinding.objects.count()) == before


def test_an_approval_binding_no_tool_answers_an_empty_list(gate):
    dep, _client, _permit, _ = _world(bind=False)
    answer = gate.get(_url(dep, "?include=tools"))
    assert answer.status_code == 200, answer.content
    assert answer.json()["tools"] == []
    assert answer.json()["version"] == str(_latest(dep).id)


@pytest.mark.parametrize(
    "query",
    [
        "?include=",
        "?include",
        "?include=TOOLS",
        "?include=tool",
        "?include=tools,contracts",
        "?include=tools&include=tools",
        "?include=tools&include=contracts",
        "?include=contracts",
        "?include=tools%20",
    ],
)
def test_any_other_include_is_refused_never_ignored(gate, query):
    dep, _client, _permit, _ = _world()
    answer = gate.get(_url(dep, query))
    assert answer.status_code == 400, (query, answer.content)
    body = answer.json()
    assert body["code"] == gate_approval.UNKNOWN_INCLUDE == "unknown_include"
    assert set(body) == {"error", "code"}, "a refused include serves nothing of the approval"


def test_the_404_and_409_answers_are_the_same_with_tools(gate):
    dep, _client, _permit, _ = _world()
    missing = f"/api/assurance/deployments/{'0' * 8}-0000-4000-8000-{'0' * 12}/workflows/{WF}/approval-in-force/"
    urls = {
        "no such workflow": _base(dep) + "workflows/no-such-workflow/approval-in-force/",
        "no such deployment": missing,
    }
    for why, url in urls.items():
        plain, with_tools = gate.get(url), gate.get(url + "?include=tools")
        assert plain.status_code == with_tools.status_code == 404, why
        assert plain.content == with_tools.content, why
    ApprovedWorkflow.objects.filter(deployment=dep, slug=WF).update(description="moved by a bulk update")
    plain, with_tools = gate.get(_url(dep)), gate.get(_url(dep, "?include=tools"))
    assert plain.status_code == with_tools.status_code == 409
    assert plain.content == with_tools.content
    assert with_tools.json()["code"] == gate_approval.HISTORY_NOT_LEVEL
    ApprovedWorkflow.objects.filter(deployment=dep, slug=WF).delete()
    plain, with_tools = gate.get(_url(dep)), gate.get(_url(dep, "?include=tools"))
    assert plain.status_code == with_tools.status_code == 404
    assert plain.content == with_tools.content


def test_the_history_level_check_covers_the_tools_as_well_as_the_digest(gate):
    """A history row that records the digest but other tools is not level with the
    approval: the version the gate signs must bind exactly the tools it was told."""
    dep, _client, _permit, _ = _world()
    latest = _latest(dep)
    # The history refuses a queryset update to every writer; the row is moved past the
    # refusals (the base manager) to make it disagree.
    ApprovalVersion._base_manager.filter(pk=latest.pk).update(tools=[["mcp_server", "crm-mcp", "f0" * 32]])

    stale = gate.get(_url(dep, "?include=tools"))

    assert stale.status_code == 409, stale.content
    assert stale.json()["code"] == gate_approval.HISTORY_NOT_LEVEL
    # Without include the answer is what it always was: the digest is level.
    assert gate.get(_url(dep)).status_code == 200


def test_the_tools_served_are_the_bindings_the_digest_was_read_from(gate, monkeypatch):
    """A write that lands right after the digest is read never shows in the tools
    served beside it: both come from one read of the bindings, in one transaction."""
    from assurance import approval_history

    dep, _client, _permit, _ = _world()
    (binding,) = _live_bindings(dep)
    real = approval_history.approvals_now

    def a_write_lands_after_the_read(deployment):
        found = real(deployment)
        # A queryset update: no signal sees it, so nothing notes the history.
        ToolContractBinding.objects.filter(pk=binding.pk).update(contract_digest="f0" * 32)
        return found

    monkeypatch.setattr(approval_history, "approvals_now", a_write_lands_after_the_read)
    answer = gate.get(_url(dep, "?include=tools"))

    assert answer.status_code == 200, answer.content
    body = answer.json()
    assert body["tools"] == [{"kind": "mcp_server", "identifier": "crm-mcp", "digest": binding.contract_digest}]
    workflow = ApprovedWorkflow.objects.get(deployment=dep, slug=WF)
    served = [SimpleNamespace(tool_kind=t["kind"], tool_identifier=t["identifier"], contract_digest=t["digest"])
              for t in body["tools"]]
    assert approval_digest(workflow, served) == body["digest"]


# ------------------------------------------------------------- v4 at the intake


def test_a_v4_document_with_exactly_its_four_verified_fields_is_recorded(service):
    dep, _client, permit, _ = _world()
    (binding,) = _live_bindings(dep)
    envelope, evidence = signed_chains.observed_effect(
        dep, WF, permit.outcome_id, _now(), schema="v4", reading=_reading(dep), approval_recipients=[LEGACY, BOUND]
    )
    verified = evidence["dispatch"]["verified"]
    assert evidence["schema"] == observed_effects.EVIDENCE_SCHEMA_V4 == "mythos.observed-effect/v4"
    assert set(verified) == FOUR == observed_effects.VERIFIED_FIELDS_V4
    assert verified["tool_contract"] == {"kind": "mcp_server", "identifier": "crm-mcp", "digest": binding.contract_digest}

    sent = _send(service, dep, envelope, evidence)

    assert sent.status_code == 201, sent.content
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=evidence["dispatch_id"])
    assert row.effect_evidence == evidence
    # v1 to v3 stay readable beside it.
    assert observed_effects.EVIDENCE_SCHEMAS == (
        "mythos.observed-effect/v1",
        "mythos.observed-effect/v2",
        "mythos.observed-effect/v3",
        "mythos.observed-effect/v4",
    )


def _v4(dep, permit, **kw):
    kw.setdefault("reading", _reading(dep))
    kw.setdefault("approval_recipients", [LEGACY, BOUND])
    return signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), schema="v4", **kw)[1]


def _verified(document):
    return document["dispatch"]["verified"]


def test_a_v4_document_with_an_extra_missing_or_malformed_verified_field_is_refused(service):
    dep, _client, permit, _ = _world()
    good = _v4(dep, permit)
    assert observed_effects.validate_evidence(good) == good

    def case(change):
        document = json.loads(json.dumps(good))
        change(document)
        return document

    def drop(*path):
        def go(d):
            target = _verified(d)
            for key in path[:-1]:
                target = target[key]
            del target[path[-1]]
        return go

    def put(value, *path):
        def go(d):
            target = _verified(d)
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
        return go

    cases = {
        "an extra verified field": put(None, "extra"),
        "the nonces block a gate might add": put([], "nonces"),
        "no tool_contract": drop("tool_contract"),
        "no approval_recipients": drop("approval_recipients"),
        "v3's two fields under v4": lambda d: d["dispatch"].update(
            verified={"approvals_digest": None, "workflow_approval": _verified(d)["workflow_approval"]}
        ),
        "a tool contract with an extra field": put("x", "tool_contract", "permissions"),
        "a tool contract with no digest": drop("tool_contract", "digest"),
        "a tool contract digest with a prefix": put("sha256:" + "c3" * 32, "tool_contract", "digest"),
        "a tool contract digest with a trailing newline": put("c3" * 32 + "\n", "tool_contract", "digest"),
        "a tool contract of no tool kind": put("agent", "tool_contract", "kind"),
        "a tool contract of another tool than the document's": put("other-mcp", "tool_contract", "identifier"),
        "a tool contract with no reading beside it": put(None, "workflow_approval"),
        "recipients that are not a list": put({}, "approval_recipients"),
        "too many recipients": put([BOUND] * (observed_effects.MAX_APPROVAL_RECIPIENTS + 1), "approval_recipients"),
        "a recipient carrying its nonce": put([{**BOUND, "nonce": "n-1"}], "approval_recipients"),
        "a recipient with no tenant": put([{k: v for k, v in BOUND.items() if k != "tenant"}], "approval_recipients"),
        "a recipient word of its own": put([{**BOUND, "recipient": "partly"}], "approval_recipients"),
        "an unbound recipient with a destination": put([{**LEGACY, "destination": "acct-42"}], "approval_recipients"),
        "a bound recipient with a null destination": put([{**BOUND, "destination": None}], "approval_recipients"),
        "a bound recipient with a null tenant": put([{**BOUND, "tenant": None}], "approval_recipients"),
        "an approval id that is not a digest": put([{**BOUND, "approval": "approval-1"}], "approval_recipients"),
        "an empty obligation": put([{**BOUND, "obligation": ""}], "approval_recipients"),
        # Sorted by (obligation, approval, recipient, destination, tenant), as Achilles
        # sorts them (observed_effect.recipient_order): "manager..." before "two...".
        "recipients out of their order": put([BOUND, LEGACY], "approval_recipients"),
    }
    for why, change in cases.items():
        with pytest.raises(observed_effects.EvidenceRefused):
            observed_effects.validate_evidence(case(change))
        assert why
    # Through the route: refused with a 400, nothing recorded.
    envelope, evidence = signed_chains.observed_effect(
        dep, WF, permit.outcome_id, _now(), schema="v4", reading=_reading(dep),
        approval_recipients=[{**BOUND, "nonce": "n-1"}],
    )
    refused = _send(service, dep, envelope, evidence)
    assert refused.status_code == 400, refused.content
    assert not WorkflowChainOutcome.objects.filter(effect_dispatch_id=evidence["dispatch_id"]).exists()


def test_the_valid_v4_shapes_are_read(service):
    dep, _client, permit, _ = _world()
    for kw in (
        {"approval_recipients": []},
        {"approval_recipients": [LEGACY]},
        {"approval_recipients": [LEGACY, BOUND]},
        {"approval_recipients": [{**BOUND, "approval": "", "destination": "", "tenant": ""}]},
        {"reading": None},  # no link: no reading, no tool contract
        {"approvals_digest": "sha256:" + "a5" * 32},
    ):
        document = _v4(dep, permit, **kw)
        assert observed_effects.validate_evidence(document) == document, kw
    assert _verified(_v4(dep, permit, reading=None))["tool_contract"] is None


def test_v3_is_read_exactly_as_before_and_carries_none_of_v4s_fields(service):
    dep, _client, permit, _ = _world()
    v3 = signed_chains.observed_effect(dep, WF, permit.outcome_id, _now(), schema="v3", reading=_reading(dep))[1]
    assert observed_effects.validate_evidence(v3) == v3
    for extra in ({"tool_contract": None}, {"approval_recipients": []}):
        carried = json.loads(json.dumps(v3))
        _verified(carried).update(extra)
        with pytest.raises(observed_effects.EvidenceRefused):
            observed_effects.validate_evidence(carried)

    class Row:
        dispatch_route_fingerprint = ""

    state = dispatch_state(v3, Row())
    assert state.gate_approval is not None and state.tool_contract is None


def test_a_v4_signed_by_a_key_this_backend_does_not_trust_is_refused(service):
    dep, _client, permit, _ = _world()
    envelope, evidence = signed_chains.observed_effect(
        dep, WF, permit.outcome_id, _now(), schema="v4", reading=_reading(dep), key=Ed25519PrivateKey.generate()
    )
    refused = _send(service, dep, envelope, evidence)
    assert refused.status_code == 400, refused.content
    assert not WorkflowChainOutcome.objects.filter(effect_dispatch_id=evidence["dispatch_id"]).exists()


def test_the_dispatch_state_carries_the_tool_contract_of_a_v4_document_only(service):
    dep, _client, permit, _ = _world()
    (binding,) = _live_bindings(dep)

    class Row:
        dispatch_route_fingerprint = ""

    v4 = _v4(dep, permit)
    assert dispatch_state(v4, Row()).tool_contract == ("mcp_server", "crm-mcp", binding.contract_digest)
    assert dispatch_state(v4, Row()).gate_approval is not None
    assert dispatch_state(_v4(dep, permit, reading=None), Row()).tool_contract is None


# --------------------------------------------------------- the gate-attested tool hop


def test_a_tool_contract_matching_the_binding_in_force_at_dispatch_is_gate_attested(service):
    dep, client, permit, _ = _world()
    (binding,) = _live_bindings(dep)
    row, evidence = _record(service, dep, permit, schema="v4", reading=_reading(dep))

    chain = _chain(client, dep, permit, row)

    invokes = _hops(chain)["invokes"]
    assert invokes["verdict"] == "proven", _readings(invokes)
    assert "contract_attested_in_force_at_dispatch" in _codes(invokes)
    assert "contract_in_force_at_dispatch" not in _codes(invokes), "the presented reading is not read beside it"
    detail = next(r["detail"] for r in invokes["proven_by"] if r["code"] == "contract_attested_in_force_at_dispatch")
    version = _latest(dep)
    assert binding.contract_digest in detail and f"version {version.id}" in detail and row.outcome_id in detail
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in _hops(chain).items()}


def test_a_tool_contract_that_contradicts_the_record_is_broken_never_attested(service):
    dep, client, permit, _ = _world()
    (binding,) = _live_bindings(dep)
    cases = {
        "another contract than the version binds": {
            "tool_contract": {"kind": "mcp_server", "identifier": "crm-mcp", "digest": "c3" * 32},
        },
        # The same, with nothing presented beside it: the binding alone contradicts it.
        "another contract than the version binds, none presented": {
            "tool_contract": {"kind": "mcp_server", "identifier": "crm-mcp", "digest": "c3" * 32},
            "presented": {**signed_chains.live_presented(dep, WF), "contracts": []},
        },
        "a version not on record": {
            "reading": _reading(dep, version=str(_latest(dep).id + 1000)),
        },
        "another contract presented beside it": {
            "presented": {
                **signed_chains.live_presented(dep, WF),
                "contracts": [{"kind": "mcp_server", "identifier": "crm-mcp", "digest": "d4" * 32}],
            },
        },
    }
    for why, kw in cases.items():
        kw.setdefault("reading", _reading(dep))
        row, _ = _record(service, dep, permit, schema="v4", **kw)
        invokes = _hops(_chain(client, dep, permit, row))["invokes"]
        assert invokes["verdict"] == "broken", (why, _readings(invokes))
        assert "contract_digest_contradicts_gate" in _codes(invokes), why
        assert "contract_attested_in_force_at_dispatch" not in _codes(invokes), why
    assert binding.contract_digest != "c3" * 32
    assert _fresh(dep).decision == Deployment.Decision.NEEDS_REMEDIATION


def test_a_version_that_binds_no_such_tool_contradicts_the_gate(service):
    dep, client, permit, _ = _world(bind=False)
    row, _ = _record(
        service, dep, permit, schema="v4", reading=_reading(dep),
        tool_contract={"kind": "mcp_server", "identifier": "crm-mcp", "digest": "c3" * 32},
    )
    invokes = _hops(_chain(client, dep, permit, row))["invokes"]
    assert invokes["verdict"] == "broken" and "contract_digest_contradicts_gate" in _codes(invokes), _readings(invokes)


def test_the_tool_hop_reads_the_binding_as_of_the_dispatch_never_the_newest(service):
    dep, client, permit, _ = _world()
    (first,) = _live_bindings(dep)
    read_before = _reading(dep)
    row, _ = _record(service, dep, permit, schema="v4", reading=read_before)
    chain = _chain(client, dep, permit, row)

    newer = _recontract(client, dep)  # a new contract, and a new approval version binding it

    assert newer != first.contract_digest
    again = client.get(_base(dep) + "authority-chains/").json()["chains"]
    invokes = _hops(next(c for c in again if c["uuid"] == chain["uuid"]))["invokes"]
    assert "contract_attested_in_force_at_dispatch" in _codes(invokes), _readings(invokes)
    assert invokes["verdict"] == "proven", _readings(invokes)

    # And the other way: a gate that read the first version and signed the newest
    # binding's contract has contradicted the record, whatever the newest binds.
    row, _ = _record(
        service, dep, permit, schema="v4", reading=read_before,
        tool_contract={"kind": "mcp_server", "identifier": "crm-mcp", "digest": newer},
    )
    invokes = _hops(_chain(client, dep, permit, row))["invokes"]
    assert invokes["verdict"] == "broken", _readings(invokes)
    assert "contract_digest_contradicts_gate" in _codes(invokes)


def test_v1_to_v3_and_a_v4_with_no_link_read_the_tool_hop_exactly_as_before(service):
    dep, client, permit, _ = _world()
    seen = {}
    for name, kw in (
        ("v2", {"schema": "v2"}),
        ("v3", {"schema": "v3", "reading": _reading(dep)}),
        ("v3, no link", {"schema": "v3", "reading": None}),
        ("v4, no link", {"schema": "v4", "reading": None}),
    ):
        row, _ = _record(service, dep, permit, **kw)
        invokes = _hops(_chain(client, dep, permit, row))["invokes"]
        assert invokes["verdict"] == "proven", (name, _readings(invokes))
        assert "contract_in_force_at_dispatch" in _codes(invokes), name
        assert "contract_attested_in_force_at_dispatch" not in _codes(invokes), name
        presented = next(r for r in invokes["proven_by"] if r["code"] == "contract_in_force_at_dispatch")
        assert presented["detail"].endswith("as presented"), name
        seen[name] = [(r["verdict"], r["code"]) for r in _readings(invokes)]
    # The same readings whatever the schema: the details differ only by each
    # dispatch's own instant.
    assert len({json.dumps(v) for v in seen.values()}) == 1, seen


def test_a_v4_edited_after_it_was_signed_never_reads_attested(service):
    dep, client, permit, _ = _world()
    row, evidence = _record(
        service, dep, permit, schema="v4", reading=_reading(dep),
        tool_contract={"kind": "mcp_server", "identifier": "crm-mcp", "digest": "c3" * 32},
    )
    edited = json.loads(json.dumps(evidence))
    (binding,) = _live_bindings(dep)
    _verified(edited)["tool_contract"]["digest"] = binding.contract_digest
    WorkflowChainOutcome.objects.filter(pk=row.pk).update(effect_evidence=edited)

    invokes = _hops(_chain(client, dep, permit, row))["invokes"]

    assert invokes["verdict"] != "proven", _readings(invokes)
    assert "contract_attested_in_force_at_dispatch" not in _codes(invokes)
    assert "dispatch_state_unrecorded" in _codes(invokes)


# ------------------------------------------------------- the rule, read in isolation


T0 = datetime(2026, 11, 2, 12, 0, tzinfo=dt_timezone.utc)
D1, D2 = "a1" * 32, "b2" * 32
C1, C2 = "c1" * 32, "c2" * 32


def _history(*rows):
    """``(record, approval digest, in force from, contract it binds crm-mcp under or None)``."""
    return tuple(
        rule.ApprovalVersion(in_force_from=at, digest=d, tools=((*CRM, c),) if c else (), record=rec)
        for rec, d, at, c in rows
    )


def _contracts(*rows):
    return {CRM: tuple(rule.ContractVersion(recorded_at=at, digest=c) for c, at in rows)}


def _gate_reading(version, digest=D1, workflow=WF):
    return rule.GateApproval(deployment="d", workflow=workflow, version=version, digest=digest, read_at=T0 - timedelta(seconds=30))


def _tool_readings(history, gate, contract, *, contracts=None, presented=None, ref="crm-mcp", at=T0):
    chain = rule.Chain(
        workflow=WF,
        hops=(rule.Hop(rule.Node("policy", WF, D1), rule.INVOKES, rule.Node("mcp_server", ref)),),
        effect_outcome_id="effect-1",
    )
    dispatch = rule.DispatchState(
        dispatched_at=at,
        epoch="running#x.0",
        permit_epoch="running#x.0",
        approval_digest=D1,
        contracts=presented or {},
        gate_approval=gate,
        tool_contract=None if contract is None else (*CRM, contract),
    )
    inputs = rule.Inputs(
        approval_history={WF: history},
        contract_history=contracts if contracts is not None else _contracts((C1, T0 - timedelta(hours=1))),
    )
    return [(r.verdict, r.code) for r in rule._approved_at_dispatch(chain, chain.hops[0].target, None, dispatch, inputs)]


ONE = _history(("7", D1, T0 - timedelta(hours=1), C1))
ATTESTED = [(rule.PROVEN, "contract_attested_in_force_at_dispatch")]
CONTRADICTED = [(rule.BROKEN, "contract_digest_contradicts_gate")]


def test_the_rule_attests_a_contract_equal_to_the_binding_and_breaks_on_any_mismatch():
    assert _tool_readings(ONE, _gate_reading("7"), C1) == ATTESTED
    assert _tool_readings(ONE, _gate_reading("7"), C2) == CONTRADICTED
    assert _tool_readings(ONE, _gate_reading("8"), C1) == CONTRADICTED  # a version not on record
    assert _tool_readings(_history(("7", D1, T0 - timedelta(hours=1), None)), _gate_reading("7"), C1) == CONTRADICTED
    assert _tool_readings(ONE, _gate_reading("7"), C1, presented={CRM: C2}) == CONTRADICTED
    assert _tool_readings(ONE, _gate_reading("7", workflow="another-workflow"), C1) == CONTRADICTED
    # An attestation of another tool than this hop's speaks for nothing here.
    assert _tool_readings(ONE, _gate_reading("7"), C1, ref="other-mcp") == [(rule.UNPROVEN, "effect_other_tool")]


def test_the_rule_reads_the_binding_as_of_the_dispatch_not_the_newest():
    # Version 9 re-binds the tool under C2 an hour AFTER the dispatch.
    later = _history(("7", D1, T0 - timedelta(hours=1), C1), ("9", D2, T0 + timedelta(hours=1), C2))
    assert _tool_readings(later, _gate_reading("7"), C1) == ATTESTED
    assert _tool_readings(later, _gate_reading("7"), C2) == CONTRADICTED


def test_the_rule_reads_a_move_between_the_read_and_the_dispatch_as_superseded_and_a_skew_as_unrecorded():
    moved = _history(("7", D1, T0 - timedelta(hours=1), C1), ("9", D2, T0 - timedelta(seconds=10), C2))
    assert _tool_readings(moved, _gate_reading("7"), C1) == [(rule.UNPROVEN, "dispatched_under_superseded_contract")]
    # Only the approval moved (same contract): superseded policy, not contract.
    reworded = _history(("7", D1, T0 - timedelta(hours=1), C1), ("9", D2, T0 - timedelta(seconds=10), C1))
    assert _tool_readings(reworded, _gate_reading("7"), C1) == [(rule.UNPROVEN, "dispatched_under_superseded_policy")]
    # The platform noted version 9 a second after the dispatch by its clock: unproven, never broken.
    skewed = _history(("7", D1, T0 - timedelta(hours=1), C1), ("9", D2, T0 + timedelta(seconds=1), C2))
    contracts = _contracts((C1, T0 - timedelta(hours=1)), (C2, T0 - timedelta(seconds=5)))
    assert _tool_readings(skewed, _gate_reading("9", D2), C2, contracts=contracts) == [
        (rule.UNPROVEN, "dispatch_state_unrecorded")
    ]


def test_the_rule_still_reads_the_tools_contract_history_at_the_dispatch():
    moved = _contracts((C1, T0 - timedelta(hours=1)), (C2, T0 - timedelta(seconds=10)))
    assert _tool_readings(ONE, _gate_reading("7"), C1, contracts=moved) == [
        (rule.UNPROVEN, "dispatched_under_superseded_contract")
    ]
    assert _tool_readings(ONE, _gate_reading("7"), C1, contracts={}) == [(rule.UNPROVEN, "dispatch_state_unrecorded")]


def test_with_no_tool_contract_the_rule_reads_the_presented_contract_as_before():
    assert _tool_readings(ONE, _gate_reading("7"), None, presented={CRM: C1}) == [
        (rule.PROVEN, "contract_in_force_at_dispatch")
    ]
    assert _tool_readings(ONE, None, None, presented={CRM: C1}) == [(rule.PROVEN, "contract_in_force_at_dispatch")]


def test_the_new_codes_are_published():
    for code in ("contract_attested_in_force_at_dispatch", "contract_digest_contradicts_gate"):
        assert code in rule.REASONS and code not in rule.RETIRED_REASONS


# ------------------------------------------------- the effect's read serves its recipients


def test_the_effects_read_serves_its_approval_recipients_as_signed(service, engine_keyring):
    dep, client, permit, _ = _world()
    row4, _ = _record(service, dep, permit, schema="v4", reading=_reading(dep), approval_recipients=[LEGACY, BOUND])
    none4, _ = _record(service, dep, permit, schema="v4", reading=_reading(dep), approval_recipients=[])
    row3, _ = _record(service, dep, permit, schema="v3", reading=_reading(dep))

    outcomes = {o["outcome_id"]: o for o in client.get(_base(dep) + "chain-outcomes/").json()["outcomes"]}

    assert outcomes[row4.outcome_id]["approval_recipients"] == [LEGACY, BOUND]
    assert [e["recipient"] for e in outcomes[row4.outcome_id]["approval_recipients"]] == ["unbound", "bound"]
    assert outcomes[none4.outcome_id]["approval_recipients"] == []
    assert outcomes[row3.outcome_id]["approval_recipients"] is None  # v3 records none
    assert outcomes[permit.outcome_id]["approval_recipients"] is None  # a permit check is no effect

    # A stored document edited after signing says nothing.
    edited = json.loads(json.dumps(row4.effect_evidence))
    _verified(edited)["approval_recipients"] = [LEGACY]
    WorkflowChainOutcome.objects.filter(pk=row4.pk).update(effect_evidence=edited)
    outcomes = {o["outcome_id"]: o for o in client.get(_base(dep) + "chain-outcomes/").json()["outcomes"]}
    assert outcomes[row4.outcome_id]["approval_recipients"] is None

    # Nor does one whose effect key this backend no longer trusts.
    keys = {k: v for k, v in signed_chains.ENGINE_KEYS.items() if k != "achilles-effect"}
    signed_chains.write_keyring(engine_keyring, keys)
    outcomes = {o["outcome_id"]: o for o in client.get(_base(dep) + "chain-outcomes/").json()["outcomes"]}
    assert outcomes[none4.outcome_id]["approval_recipients"] is None
