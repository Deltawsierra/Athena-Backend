"""The assurance policy in force — the rule set a decision is made under (SPINE).

A claim and a deployment decision are only as meaningful as the *policy* they were
evaluated against: the six-state decision thresholds, the required-evidence rules,
and the claim caps that turn a graph of findings and claims into a verdict. SPINE
Phase 1 already binds a claim to the **system state** it was true of (the
:func:`assurance.fingerprint.compute_system_fingerprint`) and stores a
``policy_version`` alongside it — but that version was a bare constant that ignored
the deployment and never fed back into invalidation, so a change to the *rules*
(not the system) could silently leave an old decision reading as if it still held.

This module closes that seam. It declares the governing policy **as documented,
machine-readable data** (mirroring the receipt standard's :data:`RECEIPT_SCHEMA`),
and pins it to a deterministic version string. The pin is derived from the *actual
governing constants* — the readiness order, the severity thresholds, the resolved
and unverified sets, the claim caps, and the evidence TTL — so a change to any of
them moves the pin even if nobody remembered to bump a version string. That pin is
stored with each claim at derivation and carried on the decision-support artifact
and the assurance receipt, so a later reconcile can ask a question it could not ask
before: *is the policy this decision was made under still the policy in force?* A
mismatch invalidates the claim through the same temporal / INVALIDATES backbone a
system-state change already runs (see :mod:`assurance.invalidation`) — a policy
change can now invalidate a decision, honestly and without a fabricated pass.

**Per deployment, honestly.** The rule set is global today: every deployment is
judged under the same thresholds, so :func:`policy_pin` returns the same pin for
every deployment. What is *per-deployment* is the **pinning**: each deployment's
claims, decisions and receipts carry their own pinned copy of the policy version
they were assessed under, so a change is detectable per deployment. The
``deployment`` argument is threaded through for that stable call site and for the
future where a deployment carries its own policy pack; it is never used to invent a
per-deployment rule that is not really declared.
"""

from __future__ import annotations

from .change import EVIDENCE_TTL_DAYS
from .decision import _READINESS_ORDER, _RESOLVED_STATUSES, _UNVERIFIED
from .models import Deployment
from .receipt import RECEIPT_VERSION, _digest

# The version of the assurance-policy standard this module emits. A stable string a
# consumer keys on; bump it on a *deliberate* policy change. The pin below also
# moves automatically when the governing constants change, so an accidental drift
# in the rules is caught even without a bump.
POLICY_VERSION = "mythos.assurance.policy/1.0"


def _policy_document() -> dict:
    """The governing assurance policy, as deterministic data. Every value is read
    from the *live* governing constant, so the pin computed over this document
    tracks the real rules rather than a hand-maintained copy of them."""
    return {
        "policy_version": POLICY_VERSION,
        # The rule-set / evaluator standard the decision is expressed in — the same
        # version the assurance receipt is stamped with, so a claim's policy and the
        # receipt that backs it never disagree about which evaluator ran.
        "evaluator_standard": RECEIPT_VERSION,
        # The six-state decision rules (see assurance.decision).
        "decision": {
            "readiness_order": [d.value for d in _READINESS_ORDER],
            # Worst active finding severity -> decision (assurance.decision
            # ._decision_from_findings). Declared here as data so a change to the
            # threshold shows up in the pin.
            "severity_thresholds": {
                "critical": Deployment.Decision.NOT_RECOMMENDED.value,
                "high": Deployment.Decision.NEEDS_REMEDIATION.value,
                "medium_or_low": Deployment.Decision.READY_RESTRICTED.value,
                "unverified_only": Deployment.Decision.NEEDS_MORE_EVIDENCE.value,
                "clean": Deployment.Decision.READY.value,
            },
            # Finding statuses that no longer count as open exposure.
            "resolved_statuses": sorted(s.value for s in _RESOLVED_STATUSES),
            # Evidence classes that read as "genuinely unknown" and drive
            # needs-more-evidence rather than a clean pass.
            "unverified_evidence_classes": sorted(e.value for e in _UNVERIFIED),
            # How a live claim caps the decision (assurance.decision
            # .claim_decision_signal). The cap can only hold a decision back.
            "claim_caps": {
                "contradicted": Deployment.Decision.NEEDS_REMEDIATION.value,
                "stale": Deployment.Decision.NEEDS_MORE_EVIDENCE.value,
                "unknown": Deployment.Decision.NEEDS_MORE_EVIDENCE.value,
                "open_retest": Deployment.Decision.NEEDS_MORE_EVIDENCE.value,
                # A person's recorded judgment that a moved obligation is material
                # (assurance.legal); a review merely pending caps nothing.
                "legally_stale": Deployment.Decision.NEEDS_MORE_EVIDENCE.value,
            },
        },
        # Required-evidence rules (assurance.claims / assurance.change).
        "required_evidence": {
            "evidence_ttl_days": EVIDENCE_TTL_DAYS,
            "verified_requires_verified_evidence": True,
            "vendor_asserted_caps_at_supported": True,
        },
    }


# A module-level snapshot for introspection ("documented + machine-readable"). It
# is the same content the pin is taken over.
POLICY = _policy_document()


def policy_pin(deployment=None) -> str:
    """The pinned assurance-policy version a decision is made under: the policy
    standard version and a short digest of the governing rules
    (``mythos.assurance.policy/1.0+<hex>``). Deterministic and timestamp-free — the
    same rules always yield the same pin, and a change to any governing threshold,
    resolved/unverified set, claim cap or evidence TTL moves it.

    ``deployment`` is accepted for a stable call site (and a future per-deployment
    policy pack); the rule set is global today, so the pin is the same for every
    deployment — what is per-deployment is that each deployment's claims and
    receipts carry their own pinned copy of it."""
    return f"{POLICY_VERSION}+{_digest(_policy_document())[:12]}"
