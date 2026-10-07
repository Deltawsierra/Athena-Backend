"""Signed sign-in and delegation records prove a chain's first two hops, from production data.

Authority chain, part 4 of the owner's 7 Oct decision. On master (b24ae55) nothing
records who signed in as whom or who delegated to which agent: a chain that starts at
a person reads ``authenticated_as`` and ``delegates_to`` unproven (``no_record``)
always, and ``POST .../authentications/`` and ``.../delegations/`` are 404.

* A real-key sign-in and a real-key delegation, posted by their collectors, prove the
  two hops; with #136's observed effect, a chain that starts at a person reads proven
  end to end and lifts the effect.
* Every refusal is named: a key mapped to another kind, a reused outcome id, a
  replayed assertion or grant record, a document that is not the one signed, another
  deployment, a witness the signer is not, a race lost at the unique column.
* Every unproven reading is named: no record, out of the window, an expired session,
  out of scope, a grant not yet open or expired, a revoked grant, no signed instant.
* Revocation is authority, read at the effect's instant: revoked after the effect,
  the effect stays proven; revoked before, it does not -- and a revocation is never
  refused for arriving late.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance.decision import decision_support
from tests import signed_chains
from tests.test_spine_authority_chain import WF, _admin, _base, _chain_body, _client, _fresh, _post, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
VECTORS = Path(__file__).resolve().parent / "vectors" / "identity-evidence-v1.json"
TOKENS = {
    "authentication": "sign-in-collector-token-for-tests-0123456789",  # pragma: allowlist secret
    "delegation": "grant-collector-token-for-tests-0123456789abc",  # pragma: allowlist secret
}


def _service(kind):
    from assurance import identity_evidence

    return {"authentication": identity_evidence.AUTHENTICATION_SERVICE, "delegation": identity_evidence.DELEGATION_SERVICE}[
        kind
    ]


@pytest.fixture
def collectors(monkeypatch):
    """Both collectors: each credential, and the account each authenticates as."""
    clients = {}
    for kind, token in TOKENS.items():
        service = _service(kind)
        User.objects.create_user(username=f"{kind}-collector", password="x")
        monkeypatch.setenv(service.token_env, token)
        monkeypatch.setenv(service.user_env, f"{kind}-collector")
        client = APIClient()
        client.credentials(**{service.meta: token})
        clients[kind] = client
    return clients


def _now(minutes=0):
    return datetime.now(dt_timezone.utc) - timedelta(minutes=minutes)


def _send(client, dep, kind, envelope, evidence):
    return client.post(_base(dep) + f"{kind}s/", {"envelope": envelope, "evidence": evidence}, format="json")


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


def _person_chain(client, dep, permit, effect_row):
    body = _chain_body(client, dep, permit, person=True)
    body["effect_outcome_id"] = effect_row.outcome_id
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    return answer.json()["chains"][0]


def _chains(client, dep):
    return [c for c in client.get(_base(dep) + "authority-chains/").json()["chains"] if c["standing"]]


def _sign_in(dep, effect_at, **kw):
    return signed_chains.authentication(dep, kw.pop("authenticated_at", effect_at - timedelta(minutes=30)), **kw)


def _grant(dep, effect_at, **kw):
    return signed_chains.delegation(
        dep,
        kw.pop("not_before", effect_at - timedelta(hours=1)),
        kw.pop("not_after", effect_at + timedelta(days=1)),
        **kw,
    )


def _world_with_effect(minutes=1):
    dep, client, permit, _ = _world()
    effect_at = _now(minutes)
    effect = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, effect_at)
    return dep, client, permit, effect, effect_at


# ------------------------------------------------- a person-started chain, proven


def test_a_chain_that_starts_at_a_person_reads_proven_end_to_end(collectors):
    dep, client, permit, effect, effect_at = _world_with_effect()
    chain = _person_chain(client, dep, permit, effect)
    assert chain["verdict"] == "unproven"
    assert _fresh(dep).decision == "needs_more_evidence"

    signed_in = _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at))
    assert signed_in.status_code == 201, signed_in.content
    assert signed_in.json()["witness"] == "mythos" and signed_in.json()["kind"] == "authentication"
    granted = _send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at))
    assert granted.status_code == 201, granted.content

    chain = _chains(client, dep)[0]
    hops = _hops(chain)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in hops.items() if h["verdict"] != "proven"}
    assert {r: _codes(h) for r, h in hops.items()} == {
        "authenticated_as": ["authentication"],
        "delegates_to": ["delegation"],
        "under_policy": ["approval_in_force"],
        "invokes": ["approved_contract_in_force", "declared_edge"],
        "through_identity": ["declared_identity"],
        "performs": ["declared_permission", "within_approval", "gate_permit"],
        "produces": ["observed_effect"],
    }
    assert "witnessed by mythos" in hops["authenticated_as"]["proven_by"][0]["detail"]
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_unproven"] == support["claims"]["authority_chains_missing"] == []
    assert support["claim_cap"] is None
    assert _fresh(dep).decision == support["composition"]["signal"]


def test_without_the_records_the_person_hops_name_what_they_lack(collectors):
    dep, client, permit, effect, _ = _world_with_effect()
    hops = _hops(_person_chain(client, dep, permit, effect))
    assert _codes(hops["authenticated_as"]) == ["no_authentication_record"]
    assert _codes(hops["delegates_to"]) == ["no_delegation_record"]


# ------------------------------------------------------------------ the refusals


def _refused(answer, says):
    assert answer.status_code == 400, answer.content
    body = answer.json()
    assert body["recorded"] == 0
    assert says in body["refused"][0]["reason"], body
    return body


@pytest.mark.parametrize("kind", ["authentication", "delegation"])
@pytest.mark.parametrize(
    "signer", ["other-kind", "achilles", "achilles-effect", "athena", "unclassified", "untrusted", "posing"]
)
def test_a_record_signed_by_a_key_not_mapped_to_its_kind_is_refused(collectors, engine_keyring, kind, signer):
    from assurance.models import IdentityEvidence

    dep, _, _, _, effect_at = _world_with_effect()
    other = {"authentication": "mythos-grant-collector", "delegation": "mythos-signin-collector"}[kind]
    own = {"authentication": "mythos-signin-collector", "delegation": "mythos-grant-collector"}[kind]
    build = _sign_in if kind == "authentication" else _grant
    if signer == "unclassified":
        signed_chains.ENGINE_KEYS["hermes"] = Ed25519PrivateKey.generate()
        signed_chains.write_keyring(engine_keyring)
        try:
            envelope, evidence = build(dep, effect_at, engine="hermes")
        finally:
            del signed_chains.ENGINE_KEYS["hermes"]
    elif signer == "untrusted":
        envelope, evidence = build(dep, effect_at, key=Ed25519PrivateKey.generate())
    elif signer == "posing":
        # The other collector's key claiming this kind's signer name: the keyring binds
        # each key to one engine, so the signature names the wrong observer.
        envelope, evidence = build(dep, effect_at, engine=own, key=signed_chains.ENGINE_KEYS[other])
    else:
        envelope, evidence = build(dep, effect_at, engine=other if signer == "other-kind" else signer)

    answer = _send(collectors[kind], dep, kind, envelope, evidence)

    assert answer.status_code == 400, answer.content
    assert not IdentityEvidence.objects.exists()
    if signer == "other-kind":
        assert f"not {kind}" in answer.json()["refused"][0]["reason"]


def test_one_key_is_never_two_kinds(tmp_path):
    from assurance import observed_outcomes

    raw = base64.b64encode(oc.raw_public_key(signed_chains.ENGINE_KEYS["mythos-signin-collector"])).decode()
    path = tmp_path / "keyring.json"
    path.write_text(
        json.dumps(
            [
                {"engine": "mythos-signin-collector", "public_key": raw},
                {"engine": "mythos-grant-collector", "public_key": raw},
            ]
        )
    )
    with pytest.raises(observed_outcomes.KeyringUnavailable, match="one key has one engine"):
        observed_outcomes.load_keyring(str(path))


def test_each_identity_signer_is_mapped_to_its_own_kind_and_nothing_else():
    from assurance import composition as comp
    from assurance import identity_evidence

    by_kind = {k: sorted(s for s, v in comp.SIGNER_EVIDENCE.items() if v == k) for k in comp.IDENTITY_EVIDENCE_KINDS}
    assert by_kind == {"authentication": ["mythos-signin-collector"], "delegation": ["mythos-grant-collector"]}
    assert comp.IDENTITY_EVIDENCE_KINDS.isdisjoint(comp.EVIDENCE_KINDS)
    # On a chain outcome an identity signer is no evidence about the chain.
    for signer in by_kind["authentication"] + by_kind["delegation"]:
        assert comp.evidence_kind(comp.BASIS_DEMONSTRATED, signer) == comp.EVIDENCE_UNCLASSIFIED
    assert set(identity_evidence.SIGNER_WITNESS) == {*by_kind["authentication"], *by_kind["delegation"]}
    for near in ("mythos_signin_collector", "Mythos-signin-collector", "mythos-signin-collectors"):
        assert comp.signer_evidence(near) == comp.EVIDENCE_UNCLASSIFIED
    from assurance import authority_chain as ac

    assert identity_evidence.PRINCIPAL_KINDS == set(ac.GRAMMAR[ac.DELEGATES_TO][0])


def test_a_reused_outcome_id_is_refused(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    envelope, evidence = _sign_in(dep, effect_at)
    assert _send(collectors["authentication"], dep, "authentication", envelope, evidence).status_code == 201
    _refused(_send(collectors["authentication"], dep, "authentication", envelope, evidence), "already recorded")


def test_an_outcome_id_recorded_as_a_chain_outcome_is_refused_here_too(collectors):
    from assurance.models import WorkflowChainOutcome

    dep, _, permit, _, effect_at = _world_with_effect()
    envelope, evidence = _sign_in(dep, effect_at)
    outcome_id = json.loads(base64.b64decode(envelope["payload"]))["outcome_id"]
    WorkflowChainOutcome.objects.filter(pk=permit.pk).update(outcome_id=outcome_id)
    _refused(_send(collectors["authentication"], dep, "authentication", envelope, evidence), f"outcome {outcome_id}")


def test_a_replayed_assertion_is_refused(collectors):
    from assurance.models import IdentityEvidence

    dep, _, _, _, effect_at = _world_with_effect()
    first = _sign_in(dep, effect_at)
    assert _send(collectors["authentication"], dep, "authentication", *first).status_code == 201
    replay = _sign_in(dep, effect_at, assertion=first[1]["assertion_digest"])
    _refused(
        _send(collectors["authentication"], dep, "authentication", *replay),
        f"assertion {first[1]['assertion_digest']} was already recorded",
    )
    assert IdentityEvidence.objects.count() == 1


def test_a_grant_recorded_twice_is_refused_by_name(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    assert _send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at)).status_code == 201
    _refused(_send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at)), "already recorded active")


def test_a_replay_that_races_past_the_check_is_still_a_named_refusal(collectors, monkeypatch):
    from assurance.models import IdentityEvidence

    dep, _, _, _, effect_at = _world_with_effect()
    first = _sign_in(dep, effect_at)
    assert _send(collectors["authentication"], dep, "authentication", *first).status_code == 201
    replay = _sign_in(dep, effect_at, assertion=first[1]["assertion_digest"])
    real = IdentityEvidence.objects.filter

    def racing(*args, **kwargs):
        if "replay_key" in kwargs:  # the first post has not committed yet
            return IdentityEvidence.objects.none()
        return real(*args, **kwargs)

    monkeypatch.setattr(IdentityEvidence.objects, "filter", racing)
    answer = _send(collectors["authentication"], dep, "authentication", *replay)
    monkeypatch.undo()
    _refused(answer, "another post recorded it first")
    assert IdentityEvidence.objects.count() == 1


def test_a_document_that_is_not_the_one_signed_is_refused(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    envelope, evidence = _sign_in(dep, effect_at)
    tampered = {**evidence, "person": "employee:mallory"}
    _refused(
        _send(collectors["authentication"], dep, "authentication", envelope, tampered),
        "not the document the signature names",
    )


def test_a_grant_whose_digest_is_not_its_own_is_refused(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    envelope, evidence = _grant(dep, effect_at)
    widened = json.loads(json.dumps(evidence))
    widened["grant"]["scope"]["actions"] = ["customer:delete", "customer:update"]
    answer = _send(collectors["delegation"], dep, "delegation", envelope, widened)
    assert answer.status_code == 400 and "grant_digest is not the grant's" in str(answer.json()["evidence"])


def test_a_record_for_another_deployment_is_refused(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    other, _, _, _ = _world()
    _refused(_send(collectors["authentication"], dep, "authentication", *_sign_in(other, effect_at)), "not this one")
    _refused(_send(collectors["delegation"], dep, "delegation", *_grant(other, effect_at)), "not this one")


def test_a_witness_the_signer_is_not_is_refused(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    _refused(
        _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at, witness="customer")),
        "witnessed by 'customer'",
    )


@pytest.mark.parametrize(
    ("build", "says"),
    [
        (lambda dep, at: _sign_in(dep, at, status=oc.NOT_DEMONSTRATED), "signed held"),
        (lambda dep, at: _sign_in(dep, at, workflow=WF), "as its workflow"),
    ],
    ids=["not-held", "a-workflow-not-its-kind"],
)
def test_an_outcome_that_is_not_a_record_of_its_kind_is_refused(collectors, build, says):
    dep, _, _, _, effect_at = _world_with_effect()
    _refused(_send(collectors["authentication"], dep, "authentication", *build(dep, effect_at)), says)


def test_a_stale_sign_in_is_refused_and_a_stale_revocation_is_not(collectors):
    """The safety rule: nothing drops a revoke. A sign-in older than the window an
    outcome is accepted in is a backfill; a revocation is taken whatever its age --
    and whether or not the grant it revokes was ever recorded here."""
    from assurance.models import IdentityEvidence

    dep, _, _, _, _ = _world_with_effect()
    old = _now(60 * 24 * 40)
    _refused(
        _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, old, observed_at=old)),
        "older than the 30-day window",
    )
    revocation = signed_chains.delegation(
        dep, old - timedelta(days=1), old + timedelta(days=1), revoked_at=old, observed_at=old
    )
    answer = _send(collectors["delegation"], dep, "delegation", *revocation)
    assert answer.status_code == 201, answer.content
    assert IdentityEvidence.objects.get(outcome_id=answer.json()["outcome_id"]).document["revocation"]["state"] == "revoked"


def test_a_revocation_repeated_word_for_word_is_refused_and_the_first_stands(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    revoked = effect_at - timedelta(minutes=5)
    assert _send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at, revoked_at=revoked)).status_code == 201
    _refused(
        _send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at, revoked_at=revoked)),
        "The revocation already recorded stands",
    )


def test_only_each_collector_may_post_its_own_kind(collectors):
    from assurance.models import IdentityEvidence

    dep, _, _, _, effect_at = _world_with_effect()
    payload = dict(zip(("envelope", "evidence"), _sign_in(dep, effect_at), strict=True))
    url = _base(dep) + "authentications/"
    assert _client(_admin()).post(url, payload, format="json").status_code == 403
    assert APIClient().post(url, payload, format="json").status_code == 401
    # The grant collector's credential does not work on the sign-in route.
    assert collectors["delegation"].post(url, payload, format="json").status_code == 401
    wrong = APIClient()
    wrong.credentials(**{_service("authentication").meta: "x" * 48})
    assert wrong.post(url, payload, format="json").status_code == 401
    assert not IdentityEvidence.objects.exists()


def test_a_record_posted_as_a_plain_signed_outcome_is_refused(collectors):
    dep, _, _, _, effect_at = _world_with_effect()
    envelope, _evidence = _sign_in(dep, effect_at)
    answer = _client(_admin()).post(_base(dep) + "chain-outcomes/observed/", envelope, format="json")
    assert answer.status_code == 400, answer.content
    assert "authentication route" in answer.json()["refused"][0]["reason"]


@pytest.mark.parametrize(
    "body",
    [{}, {"envelope": {}}, {"envelope": {}, "evidence": {}, "note": "x"}, {"envelope": {}, "evidence": {"schema": "x"}}],
    ids=["empty", "no-evidence", "extra-field", "not-the-schema"],
)
def test_a_body_that_cannot_be_read_is_refused(collectors, body):
    dep, _, _, _, _ = _world_with_effect()
    for kind in ("authentication", "delegation"):
        assert collectors[kind].post(_base(dep) + f"{kind}s/", body, format="json").status_code == 400


# ------------------------------------------------------- the unproven readings


def _chain_after(collectors, auth=None, grants=(), *, minutes=1):
    dep, client, permit, effect, effect_at = _world_with_effect(minutes)
    if auth is not None:
        assert _send(collectors["authentication"], dep, "authentication", *auth(dep, effect_at)).status_code == 201
    for grant in grants:
        answer = _send(collectors["delegation"], dep, "delegation", *grant(dep, effect_at))
        assert answer.status_code == 201, answer.content
    return dep, client, _hops(_person_chain(client, dep, permit, effect)), effect_at


@pytest.mark.parametrize(
    ("auth", "code"),
    [
        (lambda dep, at: _sign_in(dep, at, person="employee:bob"), "no_authentication_record"),
        (lambda dep, at: _sign_in(dep, at, principal="admin-user"), "no_authentication_record"),
        (
            lambda dep, at: _sign_in(dep, at, authenticated_at=at - timedelta(hours=25), expires_at=at + timedelta(hours=1),
                                     observed_at=at - timedelta(hours=25)),
            "authentication_out_of_window",
        ),
        (
            lambda dep, at: _sign_in(dep, at, authenticated_at=at + timedelta(seconds=30), observed_at=at + timedelta(seconds=30)),
            "authentication_out_of_window",
        ),
        (lambda dep, at: _sign_in(dep, at, expires_at=at - timedelta(minutes=1)), "authentication_expired"),
    ],
    ids=["another-person", "another-principal", "before-the-window", "after-the-effect", "session-expired"],
)
def test_a_sign_in_that_does_not_cover_the_effect_leaves_the_hop_unproven_and_named(collectors, auth, code):
    dep, _, hops, _ = _chain_after(collectors, auth, [_grant], minutes=2)
    assert hops["authenticated_as"]["verdict"] == "unproven"
    assert _codes(hops["authenticated_as"]) == [code]
    assert hops["delegates_to"]["verdict"] == "proven"
    assert decision_support(_fresh(dep))["claim_cap"] == "needs_more_evidence"


@pytest.mark.parametrize(
    ("grant", "code"),
    [
        (lambda dep, at: _grant(dep, at, agent="billing-agent"), "no_delegation_record"),
        (lambda dep, at: _grant(dep, at, principal=("user", "admin-user")), "no_delegation_record"),
        (lambda dep, at: _grant(dep, at, actions=("customer:read",)), "delegation_out_of_scope"),
        (lambda dep, at: _grant(dep, at, not_before=at + timedelta(seconds=1), observed_at=at), "delegation_out_of_window"),
        (lambda dep, at: _grant(dep, at, not_before=at - timedelta(hours=2), not_after=at), "delegation_expired"),
        (lambda dep, at: _grant(dep, at, revoked_at=at - timedelta(seconds=1)), "delegation_revoked"),
    ],
    ids=["another-agent", "another-principal", "out-of-scope", "not-yet-open", "expired", "revoked"],
)
def test_a_delegation_that_does_not_cover_the_effect_leaves_the_hop_unproven_and_named(collectors, grant, code):
    dep, _, hops, _ = _chain_after(collectors, _sign_in, [grant])
    assert hops["delegates_to"]["verdict"] == "unproven"
    assert _codes(hops["delegates_to"]) == [code]
    assert hops["authenticated_as"]["verdict"] == "proven"
    assert decision_support(_fresh(dep))["claim_cap"] == "needs_more_evidence"


def test_with_no_observed_effect_there_is_no_signed_instant_to_place_them_against(collectors):
    dep, client, permit, _, effect_at = _world_with_effect()
    assert _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at)).status_code == 201
    assert _send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at)).status_code == 201
    hops = _hops(_post(client, dep, _chain_body(client, dep, permit, person=True)).json()["chains"][0])
    assert _codes(hops["authenticated_as"]) == _codes(hops["delegates_to"]) == ["effect_instant_unknown"]


def test_a_record_edited_after_it_was_recorded_proves_nothing(collectors):
    from assurance.models import IdentityEvidence

    dep, client, hops, _ = _chain_after(collectors, _sign_in, [_grant])
    assert hops["authenticated_as"]["verdict"] == "proven"
    row = IdentityEvidence.objects.get(kind="authentication")
    # The append-only model refuses a save; a queryset update is what a shell could do.
    IdentityEvidence.objects.filter(pk=row.pk).update(document={**row.document, "expires_at": "2999-01-01T00:00:00.000000Z"})
    assert _codes(_hops(_chains(client, dep)[0])["authenticated_as"]) == ["no_authentication_record"]


def test_a_key_withdrawn_from_the_keyring_proves_nothing_it_signed(collectors, engine_keyring):
    dep, client, hops, _ = _chain_after(collectors, _sign_in, [_grant])
    assert hops["delegates_to"]["verdict"] == "proven"
    keys = {e: k for e, k in signed_chains.ENGINE_KEYS.items() if e != "mythos-grant-collector"}
    signed_chains.write_keyring(engine_keyring, keys)
    try:
        assert _codes(_hops(_chains(client, dep)[0])["delegates_to"]) == ["no_delegation_record"]
    finally:
        signed_chains.write_keyring(engine_keyring)


def test_a_recorded_record_is_never_rewritten_or_deleted(collectors):
    from assurance.models import IdentityEvidence, IdentityEvidenceRewriteRefused

    dep, _, _, _, effect_at = _world_with_effect()
    assert _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at)).status_code == 201
    row = IdentityEvidence.objects.get()
    row.principal = "admin-user"
    with pytest.raises(IdentityEvidenceRewriteRefused):
        row.save()
    with pytest.raises(IdentityEvidenceRewriteRefused):
        row.delete()


# --------------------------------------------------- revocation is authority


def test_a_delegation_revoked_after_the_effect_does_not_unprove_it(collectors):
    dep, client, hops, effect_at = _chain_after(collectors, _sign_in, [_grant])
    assert hops["delegates_to"]["verdict"] == "proven"
    proven = _fresh(dep).decision
    # The grant collector reports the revocation later, effective after the effect.
    answer = _send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at, revoked_at=effect_at + timedelta(seconds=30)))
    assert answer.status_code == 201, answer.content
    hop = _hops(_chains(client, dep)[0])["delegates_to"]
    assert hop["verdict"] == "proven" and "after the effect, which stands" in hop["proven_by"][0]["detail"]
    assert _fresh(dep).decision == proven


def test_a_delegation_revoked_before_the_effect_unproves_it_whenever_the_revocation_arrives(collectors):
    dep, client, permit, effect, effect_at = _world_with_effect()
    assert _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at)).status_code == 201
    assert _send(collectors["delegation"], dep, "delegation", *_grant(dep, effect_at)).status_code == 201
    chain = _person_chain(client, dep, permit, effect)
    assert chain["verdict"] == "proven"
    assert decision_support(_fresh(dep))["claim_cap"] is None

    answer = _send(
        collectors["delegation"], dep, "delegation", *_grant(dep, effect_at, revoked_at=effect_at - timedelta(seconds=30))
    )
    assert answer.status_code == 201, answer.content

    hop = _hops(_chains(client, dep)[0])["delegates_to"]
    assert hop["verdict"] == "unproven" and _codes(hop) == ["delegation_revoked"]
    support = decision_support(_fresh(dep))
    assert support["claim_cap"] == "needs_more_evidence"
    assert _fresh(dep).decision == "needs_more_evidence"


# ------------------------------------------------------- conformance vectors


def _vectors():
    return json.loads(VECTORS.read_text())


def _envelope(hexed):
    return {
        "payloadType": hexed["payloadType"],
        "payload": base64.b64encode(bytes.fromhex(hexed["payload_hex"])).decode(),
        "signatures": [
            {"keyid": s["keyid"], "sig": base64.b64encode(bytes.fromhex(s["sig_hex"])).decode()}
            for s in hexed["signatures"]
        ],
    }


def _vector_keyring(v):
    keyring = {}
    for engine, key in v["keys"].items():
        private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(key["phrase"].encode()).digest())
        raw = oc.raw_public_key(private)
        assert raw.hex() == key["public_key_hex"], engine
        keyring[oc.key_id_for(raw)] = oc.TrustedKey(raw, engine)
    return keyring


def _vector_deployment(v):
    from assurance.models import Deployment

    return Deployment.objects.create(uuid=v["deployment"], name="vectors", owner=_admin())


def _ingest_vector(dep, case, keyring, now):
    from assurance import identity_evidence

    try:
        _envelope_, evidence = identity_evidence.read_body(case["kind"], {"envelope": case["envelope"], "evidence": case["evidence"]})
    except identity_evidence.BodyRefused as exc:
        return None, str(exc)
    row, refusal = identity_evidence.ingest(dep, case["kind"], _envelope(case["envelope"]), evidence, keyring=keyring, now=now)
    return row, refusal.reason if refusal else None


def test_every_valid_vector_is_recorded():
    from assurance import identity_evidence

    v = _vectors()
    dep, keyring, now = _vector_deployment(v), _vector_keyring(v), identity_evidence.instant(v["now"])
    for case in v["valid"]:
        row, why = _ingest_vector(dep, case, keyring, now)
        assert why is None, (case["name"], why)
        assert identity_evidence.in_force(row, keyring, v["deployment"]) == case["evidence"], case["name"]
        assert row.witness == "mythos"


def test_every_invalid_vector_is_refused_with_its_reason():
    from assurance import identity_evidence

    v = _vectors()
    dep, keyring, now = _vector_deployment(v), _vector_keyring(v), identity_evidence.instant(v["now"])
    names = set()
    for case in v["invalid"]:
        row, why = _ingest_vector(dep, case, keyring, now)
        assert row is None and why is not None and case["refused"] in why, (case["name"], why)
        names.add(case["name"])
    assert {"wrong-key-kind", "wrong-key-kind-delegation", "tampered", "tampered-grant", "other-deployment"} <= names


def test_the_vectors_hop_cases_read_as_the_rule_reads_them():
    """Out of window and revoked, by the vectors: the valid records, placed against an
    effect instant, through the pure rule."""
    from assurance import authority_chain as ac
    from assurance import identity_evidence
    from tests import test_the_authority_chain_rule_is_written_down as pure

    v = _vectors()
    records = {case["name"]: case for case in v["valid"]}
    for case in v["hop_cases"]:
        effect_at = identity_evidence.instant(case["effect_at"])
        authentications, delegations = [], []
        for name in case["records"]:
            record = records[name]
            row = SimpleNamespace(outcome_id=json.loads(bytes.fromhex(record["envelope"]["payload_hex"]))["outcome_id"])
            if record["kind"] == "authentication":
                authentications.append(identity_evidence.as_authentication(row, record["evidence"]))
            else:
                delegations.append(identity_evidence.as_delegation(row, record["evidence"]))
        observed = pure._replace(pure.OBSERVED, observed_at=effect_at)
        effect = pure._replace(pure.EFFECT, effect=observed)
        inputs = pure.identity_inputs(
            authentications or [pure.SIGNED_IN], delegations or [pure.GRANT], outcomes={"gate1": pure.GATE, "eff1": effect}
        )
        result = ac.verify(pure.chain(pure.ROADMAP), inputs)
        assert pure.codes(pure.at(result, case["relation"])) == {case["expect"]}, case["name"]
