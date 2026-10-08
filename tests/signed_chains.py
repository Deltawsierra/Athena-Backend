"""Chain outcomes an engine really signed, for tests that need a run behind them.

A demonstrated row is one whose stored envelope verifies against the configured
keyring and says what the row says (``observed_outcomes.recorded_outcome_is_authentic``).
A test asserting READY from chains is asserting that runs demonstrated them, so it
needs rows like that -- a typed-in ``held`` floors at NEEDS_MORE_EVIDENCE now.

The rows are written directly rather than through ``ingest``: many of these tests
use fixed historic instants that ingest's 30-day window would refuse, and what is
under test is the read path, which re-verifies every row whichever way it arrived.

Each row is bound to the served route the deployment has as it is written -- a run
of the system as it stands, which is what a test asserting READY from chains is
asserting. A test about a route that changed after the run changes the graph after
recording (see ``test_a_route_change_reopens_what_ran_on_it``).
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mythos_core import outcome as oc

from assurance import composition as comp
from assurance import observed_outcomes
from assurance.models import WorkflowChainOutcome
from assurance.served_route import served_route_fingerprint

ENGINE_KEYS = {
    "achilles": Ed25519PrivateKey.generate(),
    "athena": Ed25519PrivateKey.generate(),
    # Achilles' observed-effect key: a key of its own, under its own observer name,
    # which the keyring files under ``achilles-effect`` and nothing else.
    "achilles-effect": Ed25519PrivateKey.generate(),
    # The identity collectors' keys (part 4 of the 7 Oct decision): one for sign-ins,
    # one for delegation grants and their revocations, each a key of its own.
    "mythos-signin-collector": Ed25519PrivateKey.generate(),
    "mythos-grant-collector": Ed25519PrivateKey.generate(),
}


def write_keyring(path, keys=None) -> None:
    keys = ENGINE_KEYS if keys is None else keys
    path.write_text(
        json.dumps(
            [
                {"engine": engine, "public_key": base64.b64encode(oc.raw_public_key(key)).decode()}
                for engine, key in keys.items()
            ]
        )
    )


def record_signed(deployment, workflow, status, observed_at, *, engine="achilles", source="") -> WorkflowChainOutcome:
    """Record ``status`` for ``workflow`` as a run by ``engine`` reported it, signed."""
    key = ENGINE_KEYS[engine]
    outcome = oc.build_outcome(
        deployment=str(deployment.uuid),
        workflow=workflow,
        status=status,
        engine=engine,
        engine_version="1.0.0",
        run_id=f"run-{uuid.uuid4().hex[:8]}",
        evidence_digest="sha256:" + "cd" * 32,
        observed_at=observed_at,
        reason="" if status == oc.HELD else "the run did not establish the chain",
    )
    envelope = oc.sign_outcome(outcome, key)
    return WorkflowChainOutcome.objects.create(
        deployment=deployment,
        workflow=workflow,
        status=status,
        basis=comp.BASIS_DEMONSTRATED,
        observed_at=observed_internal(outcome),
        source=source or f"{engine} 1.0.0 run {outcome['observer']['run_id']}",
        outcome_id=outcome["outcome_id"],
        observer_engine=engine,
        observer_key_id=oc.key_id_for(oc.raw_public_key(key)),
        evidence_digest=outcome["evidence_digest"],
        envelope=envelope,
        route_fingerprint=served_route_fingerprint(deployment),
    )


def observed_internal(outcome: dict):
    """The row's ``observed_at`` for a signed outcome -- the instant it covers."""
    return observed_outcomes._instant(outcome["observed_at"])


#: The gate's state at a test dispatch's spend: Achilles' authority epoch
#: (``<state>#<boot>.<stops>``) and operator policy, the permit's and in force alike.
GATE_EPOCH = "running#5eed0fee5eed0fee.0"
GATE_POLICY = "sha256:" + "b0" * 32
GATE_STATE = {
    "epoch": GATE_EPOCH,
    "permit_epoch": GATE_EPOCH,
    "policy_id": "support-policy",
    "policy_digest": GATE_POLICY,
    "permit_policy_digest": GATE_POLICY,
}


def live_presented(deployment, workflow, *, route=None, assertion=None, grant=None) -> dict:
    """What a dispatch made NOW would be presented under: the approval of ``workflow``
    as it stands, and the contract digest of every tool it binds (sorted) -- the
    authority an Achilles caller reads from this backend and names in
    ``effect.authority``."""
    from assurance.approval_history import approvals_now

    digest, tools = approvals_now(deployment).get(workflow, (None, []))
    return {
        "approval_digest": digest,
        "contracts": [{"kind": k, "identifier": i, "digest": d} for k, i, d in sorted(tools)],
        "route_fingerprint": route,
        "assertion_digest": assertion,
        "grant_digest": grant,
    }


#: ``observed_effect(reading=LIVE)``: the reading the gate would make now.
LIVE = object()


def live_reading(deployment, workflow, read_at=None) -> dict | None:
    """What Achilles' gate reads from this backend's approval-in-force route now
    (:mod:`assurance.gate_approval`), as it signs it into a v3 document's
    ``dispatch.verified.workflow_approval``; None when the route would refuse."""
    from assurance import gate_approval

    status, body = gate_approval.approval_in_force(deployment, workflow)
    if status != 200:
        return None
    instant = read_at if read_at is not None else datetime.now(dt_timezone.utc)
    return {
        "deployment": body["deployment"],
        "workflow": body["workflow"],
        "version": body["version"],
        "digest": body["digest"],
        "read_at": _stamp(instant),
    }


def observed_effect(
    deployment,
    workflow,
    gate_outcome_id,
    observed_at,
    *,
    tool=("mcp_server", "crm-mcp"),
    engine="achilles-effect",
    status=oc.HELD,
    dispatch_id=None,
    key=None,
    action="customer:update",
    schema="v2",
    dispatched_at=None,
    presented=None,
    gate=None,
    reading=LIVE,
    approvals_digest=None,
) -> tuple[dict, dict]:
    """``(envelope, evidence)``: what Achilles posts when its dispatch saw a permitted
    action's effect -- the ``mythos.observed-effect/v2`` document, and the outcome its
    observed-effect key signed over the document's digest.

    The ``dispatch`` block: the gate's state (:data:`GATE_STATE`, ``gate`` overriding
    any of it), the instant the dispatch left (``dispatched_at``, the effect's own
    instant by default), and what it was ``presented`` under (:func:`live_presented` by
    default: the approval and contracts as they stand when this is called).
    ``schema="v1"``: the v1 document, which records no dispatch state. ``schema="v3"``:
    the v2 block and ``verified`` -- ``approvals_digest`` and the gate's ``reading`` of
    the approval in force (:func:`live_reading` by default; None for a gate with no
    link)."""
    instant = observed_at.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    evidence = {
        "schema": f"mythos.observed-effect/{schema}",
        "deployment": str(deployment.uuid),
        "workflow": workflow,
        "tool": {"kind": tool[0], "identifier": tool[1]},
        "action": action,
        "action_digest": "ab" * 32,
        "permit_digest": "sha256:" + "ef" * 32,
        "dispatch_id": dispatch_id or uuid.uuid4().hex,
        "gate_outcome_id": gate_outcome_id,
        "observed": {
            "provider": "crm-provider",
            "status_code": 200,
            "receipt_id": "rcpt-1",
            "response_digest": "sha256:" + "12" * 32,
        },
        "observed_at": instant,
    }
    if schema in ("v2", "v3"):
        left = dispatched_at if dispatched_at is not None else observed_at
        evidence["dispatch"] = {
            **GATE_STATE,
            **(gate or {}),
            "dispatched_at": _stamp(left),
            "presented": presented if presented is not None else live_presented(deployment, workflow),
        }
    if schema == "v3":
        evidence["dispatch"]["verified"] = {
            "approvals_digest": approvals_digest,
            "workflow_approval": (
                live_reading(deployment, workflow, left - timedelta(seconds=1)) if reading is LIVE else reading
            ),
        }
    outcome = oc.build_outcome(
        deployment=str(deployment.uuid),
        workflow=workflow,
        status=status,
        engine=engine,
        engine_version="0.1.0",
        run_id=f"run-{uuid.uuid4().hex[:8]}",
        evidence_digest=oc.evidence_digest_of(evidence),
        observed_at=observed_at,
        reason="" if status == oc.HELD else "the dispatch did not observe it",
    )
    return oc.sign_outcome(outcome, key or ENGINE_KEYS[engine]), evidence


def record_observed_effect(deployment, workflow, gate_outcome_id, observed_at, **kw) -> WorkflowChainOutcome:
    """An observed effect, recorded the one way one is: verified and taken in whole
    (:func:`assurance.observed_outcomes.ingest`, with its evidence)."""
    envelope, evidence = observed_effect(deployment, workflow, gate_outcome_id, observed_at, **kw)
    rows, refusals = observed_outcomes.ingest(deployment, [envelope], evidence=[evidence])
    assert not refusals, refusals
    return rows[0]


def _stamp(instant) -> str:
    return instant.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sign_record(deployment, kind, evidence, observed_at, *, engine, key=None, status=oc.HELD, workflow=None):
    outcome = oc.build_outcome(
        deployment=str(deployment.uuid),
        workflow=workflow or kind,
        status=status,
        engine=engine,
        engine_version="0.1.0",
        run_id=f"run-{uuid.uuid4().hex[:8]}",
        evidence_digest=oc.evidence_digest_of(evidence),
        observed_at=observed_at,
        reason="" if status == oc.HELD else "the collector did not establish it",
    )
    return oc.sign_outcome(outcome, key or ENGINE_KEYS[engine])


def authentication(
    deployment,
    authenticated_at,
    *,
    person="employee",
    principal="support-user",
    expires_at=None,
    observed_at=None,
    assertion=None,
    witness="mythos",
    engine="mythos-signin-collector",
    key=None,
    status=oc.HELD,
    workflow=None,
) -> tuple[dict, dict]:
    """``(envelope, evidence)``: what the sign-in collector posts when the identity
    provider's log shows ``person`` signed in as ``principal`` -- the
    ``mythos.authentication/v1`` document, and the outcome its key signed over it."""
    from datetime import timedelta

    observed_at = observed_at or authenticated_at
    evidence = {
        "schema": "mythos.authentication/v1",
        "deployment": str(deployment.uuid),
        "person": person,
        "principal": principal,
        "identity_provider": {"issuer": "https://idp.example.test", "protocol": "oidc"},
        "assertion_digest": assertion or "sha256:" + uuid.uuid4().hex * 2,
        "authenticated_at": _stamp(authenticated_at),
        "expires_at": _stamp(expires_at or authenticated_at + timedelta(hours=8)),
        "witness": witness,
        "observed_at": _stamp(observed_at),
    }
    envelope = _sign_record(
        deployment, "authentication", evidence, observed_at, engine=engine, key=key, status=status, workflow=workflow
    )
    return envelope, evidence


def delegation(
    deployment,
    not_before,
    not_after,
    *,
    principal=("user", "support-user"),
    agent="support-agent",
    actions=("customer:update",),
    grant_id="grant-1",
    revoked_at=None,
    observed_at=None,
    witness="mythos",
    engine="mythos-grant-collector",
    key=None,
    status=oc.HELD,
) -> tuple[dict, dict]:
    """``(envelope, evidence)``: what the grant collector posts for a grant of
    ``actions`` from ``principal`` to ``agent`` over ``[not_before, not_after)`` -- or,
    with ``revoked_at``, for its revocation."""
    from assurance.identity_evidence import grant_digest

    grant = {
        "grant_id": grant_id,
        "principal": {"kind": principal[0], "ref": principal[1]},
        "agent": agent,
        "scope": {"actions": sorted(set(actions))},
        "not_before": _stamp(not_before),
        "not_after": _stamp(not_after),
    }
    observed_at = observed_at or revoked_at or not_before
    evidence = {
        "schema": "mythos.delegation/v1",
        "deployment": str(deployment.uuid),
        "grant": grant,
        "grant_digest": grant_digest(str(deployment.uuid), grant),
        "revocation": (
            {"state": "revoked", "revoked_at": _stamp(revoked_at)}
            if revoked_at is not None
            else {"state": "active", "revoked_at": None}
        ),
        "witness": witness,
        "observed_at": _stamp(observed_at),
    }
    return _sign_record(deployment, "delegation", evidence, observed_at, engine=engine, key=key, status=status), evidence


def record_identity(deployment, kind, envelope, evidence):
    """A sign-in or delegation record, recorded the one way one is: verified and taken
    in whole (:func:`assurance.identity_evidence.ingest`)."""
    from assurance import identity_evidence

    row, refusal = identity_evidence.ingest(deployment, kind, envelope, evidence)
    assert refusal is None, refusal
    return row
