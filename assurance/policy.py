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
governing constants* — the readiness order, the severity thresholds, the resolved,
unverified and untrusted-severity sets, the claim, acceptance, scan and coverage
caps, the chain floors and the route and evidence rules, the latent-condition
states, and the evidence TTL — each read off the module that applies it, so a
change to any of them moves the pin even if nobody remembered to bump a version
string. That pin is
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

# Modules, not names: every rule is read off the module that applies it at the moment
# the pin is taken, so a rule changed there -- in a release, or by a test -- is the
# rule named here. Names imported at load time were copies the decision code no
# longer read, and changing the rule left the pin where it was.
from . import change as _change
from . import composition as _composition
from . import coverage as _coverage
from . import decision as _decision
from . import models as _models
from . import workflow_chains as _workflow_chains
from .receipt import RECEIPT_VERSION, _digest

# The version of the assurance-policy standard this module emits. A stable string a
# consumer keys on; bump it on a *deliberate* policy change. The pin below also
# moves automatically when the governing constants change, so an accidental drift
# in the rules is caught even without a bump.
POLICY_VERSION = "mythos.assurance.policy/1.0"


def _value(state) -> str:
    """A decision state as its stored string."""
    return str(getattr(state, "value", state))


def _values(states) -> list[str]:
    """A set of states as sorted strings."""
    return sorted(_value(s) for s in states)


def _table(mapping) -> dict:
    """A table of rules as plain strings, keyed and valued."""
    return {_value(k): (v if isinstance(v, int) else _value(v)) for k, v in mapping.items()}


def _policy_document() -> dict:
    """The governing assurance policy, as deterministic data.

    Every cap, floor, threshold, order, rank and state set the decision applies is
    here, and each is read from the constant the decision code itself applies -- the
    very object, off its module, at the moment the pin is taken -- so the pin
    computed over this document tracks the rules rather than a hand-maintained copy
    of them. That includes the orders the thresholds are measured against: the
    severity order every finding threshold and every acceptance is ranked in
    (``models.SEVERITY_ORDER``), the evidence-strength order a finding's weakest
    evidence is read with, the chain rule's own readiness order and ranks, and what
    an unsigned basis counts as. A reordered severity scale changed the decision of
    the same stored inputs and left the pin -- and every decision stamped under it --
    where it was. Adding a rule means adding the constant the code reads to this
    document; a test holds every constant of the modules the decision is computed in
    either to moving the pin or to a named reason it is not a rule, and each listed
    one to being what the decision applies
    (tests/test_an_accepted_risk_is_carried_not_removed.py)."""
    decision = _decision
    composition = _composition
    return {
        "policy_version": POLICY_VERSION,
        # The rule-set / evaluator standard the decision is expressed in — the same
        # version the assurance receipt is stamped with, so a claim's policy and the
        # receipt that backs it never disagree about which evaluator ran.
        "evaluator_standard": RECEIPT_VERSION,
        # The six-state decision rules (see assurance.decision).
        "decision": {
            # Best to worst: the order every "worse of" is taken in.
            "readiness_order": sorted(
                (_value(d) for d in decision._READINESS_RANK), key=lambda d: decision._READINESS_RANK[d]
            ),
            # The order severities are ranked in, weakest first (assurance.models
            # .severity_rank): every threshold below, and whether an acceptance covers
            # a finding's severity (assurance.decision._acceptance_covers), is read
            # against it.
            "severity_order": [_value(s) for s in _models.SEVERITY_ORDER],
            # Strongest first: a finding's evidence class is its weakest evidence
            # row's by this order (assurance.models.evidence_strength), and that is
            # what the unverified set below is matched against.
            "evidence_strength_order": [_value(e) for e in _models.EVIDENCE_STRENGTH_ORDER],
            # Worst active finding severity -> decision (assurance.decision
            # ._decision_from_findings): the first threshold reached decides.
            "severity_thresholds": {
                "at_or_above": [[_value(t), _value(d)] for t, d in decision.FINDING_SEVERITY_DECISIONS],
                "unverified_only": _value(decision.FINDING_UNVERIFIED_ONLY),
                "clean": _value(decision.FINDING_CLEAN),
            },
            # Finding statuses that no longer count as open exposure.
            "resolved_statuses": _values(decision._RESOLVED_STATUSES),
            # Evidence classes that read as "genuinely unknown" and drive
            # needs-more-evidence rather than a clean pass.
            "unverified_evidence_classes": _values(decision._UNVERIFIED),
            # Finding statuses whose recorded severity no longer places the
            # deployment (an INVALIDATED finding): each counts as unverified.
            "untrusted_severity_statuses": _values(decision.UNTRUSTED_SEVERITY_STATUSES),
            # What an assessment that found nothing contributes: a scan run to
            # completion, and a complete audit (assurance.coverage).
            "assessed_clean": {
                "completed_scan": _value(decision.COMPLETED_SCAN_SIGNAL),
                "complete_audit": _value(_coverage.COMPLETE_AUDIT_SIGNAL),
            },
            # A scan the engine stopped early, and a coverage gap on the critical
            # path or a check a scan fell short of.
            "scan_incomplete_cap": _value(decision.SCAN_INCOMPLETE_CAP),
            "coverage_cap": _value(_coverage.COVERAGE_CAP),
            # How a live claim caps the decision (assurance.decision
            # .claim_decision_signal). The cap can only hold a decision back.
            "claim_caps": _table(decision.CLAIM_CAPS),
            # The legal-axis values that cap: a person's recorded judgment.
            "legally_stale_statuses": _values(decision._LEGALLY_STALE),
            # The latent-condition states a claim cannot be read in, and the ones it
            # is held in (assurance.latent).
            "latent_unread_states": _values(decision.LATENT_UNREAD_STATES),
            "latent_holding_states": _values(decision.LATENT_HOLDING_STATES),
            # How a risk a person accepted caps the decision (owner decision Q6,
            # assurance.decision.accepted_risk_signal). "accepted" is among the
            # resolved statuses above for every deriver; for the decision it is
            # carried, never removed.
            "accepted_risk_caps": _table(decision.ACCEPTED_RISK_CAPS),
            # The floor each chain status puts under the decision
            # (assurance.composition.FLOORS), and what a held on an approved
            # workflow counts as when it rests on no run, or on a run of a route
            # that no longer serves (assurance.composition._floor_of).
            "chain_floors": _table(composition.FLOORS),
            # The chain rule's own readiness order, and the rank it takes the worse
            # of two floors by (assurance.composition._RANK), which is read at every
            # composition -- not the order it was built from at import.
            "chain_readiness_order": [_value(s) for s in composition.READINESS_ORDER],
            "chain_readiness_rank": _table(composition._RANK),
            # The vocabulary an outcome is checked against: what the rule accepts is
            # part of what it computes.
            "chain_statuses": _values(composition.CHAIN_STATUSES),
            "chain_bases": _values(composition.CHAIN_BASES),
            "chain_routes": _values(composition.CHAIN_ROUTES),
            "evidence_kinds": _values(composition.EVIDENCE_KINDS),
            "demonstrated_statuses": _values(composition.DEMONSTRATED),
            "unexercised_bases": _values(composition.UNEXERCISED_BASES),
            "off_route": _values(composition.OFF_ROUTE),
            # Which outcomes displace earlier ones, and how a tie among the
            # survivors is broken: the one that stands is the one the floor is read
            # from.
            "verdicts": _values(composition.VERDICTS),
            "basis_rank": _table(composition._BASIS_RANK),
            "route_rank": _table(composition._ROUTE_RANK),
            "evidence_rank": _table(composition._EVIDENCE_RANK),
            # Which signer's outcomes are which kind of evidence, and what an
            # unsigned basis counts as (assurance.composition.evidence_kind).
            "signer_evidence": _table(composition.SIGNER_EVIDENCE),
            "unsigned_evidence": _table(composition._UNSIGNED_EVIDENCE),
            # How the workflow chains cap it (assurance.workflow_chains
            # .composition_decision_signal): a held resting on a permit check or an
            # unclassified signer is ready with restrictions at best; one resting on
            # no run, or taken against a route that no longer serves, counts as not
            # demonstrated.
            # The order the chain caps are taken the worse of in
            # (assurance.workflow_chains._worse), read there by its own name.
            "chain_cap_order": [_value(s) for s in _workflow_chains.READINESS_ORDER],
            "chain_caps": {
                **_table(_workflow_chains.CHAIN_CAPS),
                "held_unexercised": _value(composition.FLOORS[composition.NOT_DEMONSTRATED]),
                "held_off_route": _value(composition.FLOORS[composition.NOT_DEMONSTRATED]),
            },
        },
        # Required-evidence rules (assurance.claims / assurance.change).
        "required_evidence": {
            "evidence_ttl_days": _change.EVIDENCE_TTL_DAYS,
            "verified_requires_verified_evidence": True,
            "vendor_asserted_caps_at_supported": True,
        },
    }


# A module-level snapshot for introspection ("documented + machine-readable"). It
# is the same content the pin is taken over, as it stood when this module loaded;
# the pin itself is always taken over the rules as they stand.
POLICY = _policy_document()


def policy_pin(deployment=None) -> str:
    """The pinned assurance-policy version a decision is made under: the policy
    standard version and a short digest of the governing rules
    (``mythos.assurance.policy/1.0+<hex>``). Deterministic and timestamp-free — the
    same rules always yield the same pin, and a change to any cap, floor, threshold
    or state set the decision applies, or to the evidence TTL, moves it.

    ``deployment`` is accepted for a stable call site (and a future per-deployment
    policy pack); the rule set is global today, so the pin is the same for every
    deployment — what is per-deployment is that each deployment's claims and
    receipts carry their own pinned copy of it."""
    return f"{POLICY_VERSION}+{_digest(_policy_document())[:12]}"
