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
from datetime import timezone as dt_timezone

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
) -> tuple[dict, dict]:
    """``(envelope, evidence)``: what Achilles posts when its dispatch saw a permitted
    action's effect -- the ``mythos.observed-effect/v1`` document, and the outcome its
    observed-effect key signed over the document's digest."""
    instant = observed_at.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    evidence = {
        "schema": "mythos.observed-effect/v1",
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
