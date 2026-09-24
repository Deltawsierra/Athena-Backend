"""Chain outcomes an engine really signed, for tests that need a run behind them.

A demonstrated row is one whose stored envelope verifies against the configured
keyring and says what the row says (``observed_outcomes.recorded_outcome_is_authentic``).
A test asserting READY from chains is asserting that runs demonstrated them, so it
needs rows like that -- a typed-in ``held`` floors at NEEDS_MORE_EVIDENCE now.

The rows are written directly rather than through ``ingest``: many of these tests
use fixed historic instants that ingest's 30-day window would refuse, and what is
under test is the read path, which re-verifies every row whichever way it arrived.
"""

from __future__ import annotations

import base64
import json
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mythos_core import outcome as oc

from assurance import composition as comp
from assurance import observed_outcomes
from assurance.models import WorkflowChainOutcome

ENGINE_KEYS = {"achilles": Ed25519PrivateKey.generate(), "athena": Ed25519PrivateKey.generate()}


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
    """Record ``status`` for ``workflow`` as a run by ``engine`` observed it, signed."""
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
    )


def observed_internal(outcome: dict):
    """The row's ``observed_at`` for a signed outcome -- the instant it covers."""
    return observed_outcomes._instant(outcome["observed_at"])
