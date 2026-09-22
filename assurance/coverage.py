"""The Coverage Manifest — what was assessed, and what was not (Phase 2 item 1).

Authentic evidence is not enough. If three agents, seven tools and two MCP servers
were assessed but four, nine and three exist, every captured fact can be genuine
and the assessment still be incomplete — and a decision computed only from what was
inspected reads READY because everything inspected looked good.

This module answers the question the finding count cannot: **what did we not look
at?** It tracks three sets per deployment and compares them.

- **Expected** — what the customer *declares* the system is
  (:class:`~assurance.models.DeclaredComponent`). It is the promise the assessment
  is measured against; without a declaration there is nothing to be short of, and
  the manifest says so rather than reading silence as completeness.
- **Observed** — what discovery actually *found*
  (:class:`~assurance.models.Asset`). Observed can exceed Expected: that is shadow
  infrastructure, and :mod:`assurance.bom_drift` already computes it.
- **Assessed** — what something actually *tested* (``Asset.assessed_at``).

The third is the new one, and it is new because it cannot be derived. Observing an
asset is not assessing it: discovery finding that an MCP server exists says nothing
about whether anything probed it. Nor can coverage be read off the findings — a
clean test leaves none, so "no finding on this asset" means *either* "tested and
clean" *or* "never tested", and those are the two answers that must not be
confused. So assessment is recorded when it happens, by whatever did it, and an
asset nothing has recorded assessing is **unassessed**, never "assessed and clean".

The critical path
-----------------
Not every gap should hold a release, and inventing a taxonomy of which component
kinds "matter" would be one more thing nobody agreed to. So the critical path is
built only from facts somebody already recorded deliberately:

- every **declared** component — the customer said the system has it, so shipping
  without testing it is a gap in what was promised; and
- every asset classified **HIGH_RISK** — a deriver or a human said so explicitly.

An undeclared, un-flagged asset still appears in the manifest and still counts
against completeness. It does not on its own hold the decision, because the honest
thing to do with a component nobody declared and nobody flagged is to report it,
not to block on it.
"""

from __future__ import annotations

from typing import Any

from django.utils import timezone

from .models import Asset, DeclaredComponent, Deployment

# The coverage verdicts. Deliberately three, not two: "nothing to compare against"
# is its own answer, and collapsing it into either of the others is the silent zero
# this module exists to prevent.
COMPLETE = "complete"
INCOMPLETE = "incomplete"
UNDECLARED = "undeclared"


def _component_key(kind: str, name: str, identifier: str) -> tuple[str, str]:
    """The identity two records are matched on: kind plus identifier, or kind plus
    name when no identifier was given. Mirrors :mod:`assurance.bom_drift` so the
    drift assessment and the manifest never disagree about what is the same thing.
    """
    return (str(kind or ""), str(identifier or name or "").strip().lower())


def _entity(asset: Asset) -> dict[str, Any]:
    return {
        "asset_uuid": str(asset.uuid),
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "name": asset.name,
        "identifier": asset.identifier,
        "classification": asset.classification,
        "assessed_at": asset.assessed_at.isoformat() if asset.assessed_at else None,
        "assessed_by": asset.assessed_by or None,
    }


def _declared_entity(component: DeclaredComponent) -> dict[str, Any]:
    return {
        "declared_uuid": str(component.uuid),
        "kind": component.kind,
        "kind_label": component.get_kind_display(),
        "name": component.name,
        "identifier": component.identifier,
    }


def coverage_manifest(deployment: Deployment) -> dict[str, Any]:
    """The three tallies, the entities behind them, and what that makes the audit.

    Pure and read-only; it persists nothing. The shape is built to be quotable in a
    report as it stands — "Expected 22 / Observed 21 / Assessed 19 → INCOMPLETE",
    with the specific missing entities named, because a completeness percentage
    with nothing named is a number a reader cannot act on.
    """
    declared = list(deployment.declared_components.all())
    assets = list(deployment.assets.all())

    declared_index = {
        _component_key(c.kind, c.name, c.identifier): c for c in declared
    }
    asset_index = {_component_key(a.kind, a.name, a.identifier): a for a in assets}

    assessed = [a for a in assets if a.assessed_at is not None]
    unassessed = [a for a in assets if a.assessed_at is None]

    # Declared components with nothing observed for them at all: not merely
    # untested but missing, which is a stronger statement and belongs in its own
    # list. `bom_drift` reports the same gap from the drift side.
    never_observed = [
        _declared_entity(c)
        for key, c in declared_index.items()
        if key not in asset_index
    ]
    never_observed.sort(key=lambda c: (c["kind"], c["name"]))

    # Declared AND observed, but never assessed: the case this manifest exists for.
    declared_unassessed = [
        _entity(asset)
        for key, asset in asset_index.items()
        if key in declared_index and asset.assessed_at is None
    ]
    declared_unassessed.sort(key=lambda c: (c["kind"], c["name"]))

    high_risk_unassessed = [
        _entity(asset)
        for asset in unassessed
        if asset.classification == Asset.Classification.HIGH_RISK
    ]
    high_risk_unassessed.sort(key=lambda c: (c["kind"], c["name"]))

    # Everything unassessed, declared or not, so the manifest is a complete
    # statement rather than only the part that blocks.
    unassessed_entities = [_entity(a) for a in unassessed]
    unassessed_entities.sort(key=lambda c: (c["kind"], c["name"]))

    critical_gap = bool(never_observed or declared_unassessed or high_risk_unassessed)

    if not declared:
        # Nothing was declared, so there is no promise to be short of. This is NOT
        # "complete": it is the absence of the baseline that completeness is
        # measured against, and calling it complete would turn a missing
        # declaration into a clean bill -- the same mistake `bom_drift` refuses to
        # make with `has_declared`.
        verdict = UNDECLARED
    elif critical_gap:
        verdict = INCOMPLETE
    else:
        verdict = COMPLETE

    return {
        "expected": len(declared),
        "observed": len(assets),
        "assessed": len(assessed),
        "verdict": verdict,
        "complete": verdict == COMPLETE,
        # The gap that holds a decision, separate from the gap that is merely
        # reported, so a reader can tell which is which without recomputing it.
        "critical_gap": critical_gap,
        "has_declared_baseline": bool(declared),
        "never_observed": never_observed,
        "declared_but_unassessed": declared_unassessed,
        "high_risk_unassessed": high_risk_unassessed,
        "unassessed": unassessed_entities,
        "summary": (
            f"Expected {len(declared)} / Observed {len(assets)} / "
            f"Assessed {len(assessed)} -> {verdict.upper()}"
        ),
    }


def complete_audit_signal(deployment: Deployment) -> str | None:
    """READY when a complete audit found nothing, else ``None``.

    The counterpart to :func:`coverage_decision_cap`, and the reason coverage is
    worth recording rather than only reporting: "every declared component was
    assessed and nothing was found" is a positive result, and without it such a
    deployment has no findings and therefore reads as *unassessed* -- the same
    answer as one nobody has ever looked at.

    Folded into the finding signal with ``_worse``, so it is a floor and not a cap:
    it can lift an unassessed deployment to READY and cannot make any real state
    look better. UNDECLARED never lifts anything -- there was no baseline to be
    complete against.
    """
    manifest = coverage_manifest(deployment)
    if manifest["verdict"] == COMPLETE:
        return Deployment.Decision.READY
    return None


def coverage_decision_cap(deployment: Deployment) -> str | None:
    """The cap an incomplete audit imposes on the deployment decision, or ``None``.

    A critical-path gap caps at AUDIT_INCOMPLETE: the deployment cannot be READY
    while something the customer declared, or something flagged high risk, has
    never been assessed. Like every other cap in :mod:`assurance.decision` it can
    only hold a decision back, never improve one -- a critical finding still
    outranks it, because "we found something bad" is a worse answer than "we did
    not look everywhere".

    A deployment with no declared baseline gets no cap. That is not a judgment that
    it is fine: it is the absence of the thing a cap would be measured against, and
    it is reported as UNDECLARED in the manifest rather than being turned into a
    blocking verdict nobody can act on. The way to make it actionable is to declare
    the architecture, which is a human step.
    """
    if not deployment.declared_components.exists():
        return None
    manifest = coverage_manifest(deployment)
    if manifest["critical_gap"]:
        return Deployment.Decision.AUDIT_INCOMPLETE
    return None


def record_assessment(assets, *, assessed_by: str, when=None) -> int:
    """Record that ``assets`` were assessed, by ``assessed_by``. Returns the count.

    The only way an asset becomes Assessed. Deliberately explicit and deliberately
    narrow: nothing infers assessment from the existence of an asset, from a scan
    having run, or from the absence of a finding, because each of those would put
    an asset in the Assessed column that nothing tested.
    """
    assets = [a for a in assets if a is not None]
    if not assets:
        return 0
    stamp = when or timezone.now()
    for asset in assets:
        asset.assessed_at = stamp
        asset.assessed_by = assessed_by[:128]
        asset.save(update_fields=["assessed_at", "assessed_by"])
    return len(assets)
