"""The Coverage Manifest — what was assessed, and what was not (Phase 2 item 1).

Authentic evidence is not enough. If three agents, seven tools and two MCP servers
were assessed but four, nine and three exist, every captured fact can be genuine
and the assessment still be incomplete — and a decision computed only from what was
inspected reads READY because everything inspected looked good.

This module answers the question the finding count cannot: **what did we not look
at?** It does so on two axes, because there are two ways to miss something.

The first is breadth over the inventory: which *components* were assessed. It
tracks three sets per deployment and compares them.

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

The second axis is the question set: which *checks* ran. It is not derivable from
the first and does not overlap it. ``Asset.assessed_at`` records that something
assessed a component; it cannot say what was asked of it. A deployment whose every
declared component was assessed -- by an engine that never ran the TLS check
because the target was cleartext, and never ran the object-level authorisation
check because no second identity was configured -- reads COMPLETE on the asset
axis and is nothing of the kind. The engine reports its own manifest and ingest
stores it on :attr:`~assurance.models.Deployment.check_coverage`.

The two axes differ in one way that matters for the decision. The asset axis has
no baseline unless the customer declares one, which is why UNDECLARED exists. The
check axis brings its own: the engine knows the whole list of checks it can run,
so a check that did not run is a gap against a baseline nobody had to remember to
write down. That makes it the one coverage gap that can cap a decision on a
deployment with no declared architecture at all.

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

from .graph_refs import in_graph
from .component_identity import by_identity, component_key
from .models import Asset, DeclaredComponent, Deployment

# The coverage verdicts. Deliberately three, not two: "nothing to compare against"
# is its own answer, and collapsing it into either of the others is the silent zero
# this module exists to prevent.
COMPLETE = "complete"
INCOMPLETE = "incomplete"
UNDECLARED = "undeclared"


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


# The check states the engine reports. Mirrored here rather than imported, because
# the engine is a separate deployable on its own release cycle: a value it adds is
# a value this side must learn about deliberately, and an unrecognised state must
# not silently read as one of these.
CHECK_PERFORMED = "performed"
CHECK_DEGRADED = "degraded"
CHECK_NOT_PERFORMED = "not_performed"
CHECK_UNMEASURED = "unmeasured"


def _checks_section(deployment: Deployment) -> dict[str, Any]:
    """What the latest scan said about which checks it ran.

    ``reported: False`` when no engine has said -- distinct in every direction
    from "every check ran". A caller that cannot tell those apart has the bug
    this module exists to prevent, so the flag is first in the dict and the
    counts are all None when it is False.
    """
    stored = deployment.check_coverage if isinstance(deployment.check_coverage, dict) else {}
    rows = stored.get("checks")
    unreadable = stored.get("unreadable")
    unreadable = unreadable if isinstance(unreadable, int) and unreadable > 0 else 0
    if not isinstance(rows, list):
        rows = []
    # Defensive, and asymmetrically so on purpose: `check_coverage` is type-guarded
    # above but nothing guarded its rows, so a fixture load, a data migration or a
    # shell session could put a string in the list and crash the decision, the
    # receipt and the API on a `.get`.
    rows = [r for r in rows if isinstance(r, dict)]
    if not rows and not unreadable:
        return {
            "reported": False,
            "complete": None,
            "total": None,
            "performed": None,
            "not_performed": [],
            "degraded": [],
            "unmeasured": [],
            "unrecognised": [],
            "limitations": {},
            "notes": stored.get("notes") or [],
            "reported_at": None,
            "summary": "No engine reported which checks it ran.",
        }

    not_performed = [r for r in rows if r.get("state") == CHECK_NOT_PERFORMED]
    degraded = [r for r in rows if r.get("state") == CHECK_DEGRADED]
    unmeasured = [r for r in rows if r.get("state") == CHECK_UNMEASURED]
    performed = [r for r in rows if r.get("state") == CHECK_PERFORMED]
    # A state none of the four. The engine is a separate deployable, so a state it
    # adds arrives here before this side learns the word -- and it used to be
    # counted against `complete` (correct) while appearing in no named list, so an
    # operator saw a shortfall of four with three rows and no way to learn which
    # check the fourth was. Named now, in its own bucket, which is also where a row
    # whose `state` key the engine renamed lands.
    _KNOWN = {CHECK_PERFORMED, CHECK_DEGRADED, CHECK_NOT_PERFORMED, CHECK_UNMEASURED}
    unrecognised = [r for r in rows if r.get("state") not in _KNOWN]

    total = len(rows) + unreadable
    return {
        "reported": True,
        # Only when every check performed. Degraded and unmeasured both fall
        # short: one lost probes, the other cannot say what it looked at. A row
        # this side could not read is in the total and never in `performed`, so it
        # falls short too -- an unparsable row must cap the decision, not shrink
        # the denominator until the ones left look complete.
        "complete": len(performed) == total,
        "total": total,
        "performed": len(performed),
        # Rows, not names: a reader needs the reason, and a check that did not run
        # without a stated reason is the thing this replaces.
        "not_performed": sorted(not_performed, key=lambda r: r.get("check", "")),
        "degraded": sorted(degraded, key=lambda r: r.get("check", "")),
        "unmeasured": sorted(unmeasured, key=lambda r: r.get("check", "")),
        "unrecognised": sorted(unrecognised, key=lambda r: r.get("check", "")),
        "limitations": stored.get("limitations") or {},
        "notes": stored.get("notes") or [],
        "reported_at": (
            deployment.check_coverage_at.isoformat()
            if deployment.check_coverage_at else None
        ),
        "summary": (
            f"{len(performed)} of {total} checks performed"
            + (f"; {len(not_performed)} never ran" if not_performed else "")
            + (f"; {len(degraded)} degraded" if degraded else "")
            + (f"; {len(unmeasured)} unmeasured" if unmeasured else "")
            + (
                f"; {len(unrecognised)} in a state this deployment does not know"
                if unrecognised else ""
            )
            + (f"; {unreadable} row(s) could not be read" if unreadable else "")
        ),
    }


def checks_gap(deployment: Deployment) -> bool:
    """Did the latest scan leave a check unasked, or asked incompletely?

    False when nothing was reported: silence is not a gap, the same way it is not
    completeness. The gap has to be something an engine actually said.
    """
    section = _checks_section(deployment)
    return bool(section["reported"] and not section["complete"])


def coverage_manifest(deployment: Deployment) -> dict[str, Any]:
    """The three tallies, the entities behind them, and what that makes the audit.

    Pure and read-only; it persists nothing. The shape is built to be quotable in a
    report as it stands — "Expected 22 / Observed 21 / Assessed 19 → INCOMPLETE",
    with the specific missing entities named, because a completeness percentage
    with nothing named is a number a reader cannot act on.
    """
    declared = list(deployment.declared_components.all())
    assets = in_graph(deployment.assets.all())

    declared_groups = by_identity(declared)
    observed_groups = by_identity(assets)

    assessed = [a for a in assets if a.assessed_at is not None]
    unassessed = [a for a in assets if a.assessed_at is None]

    # Declared components with nothing observed for them at all: not merely
    # untested but missing, which is a stronger statement and belongs in its own
    # list. `bom_drift` reports the same gap from the drift side.
    never_observed = [
        _declared_entity(c)
        for c in declared
        if component_key(c.kind, identifier=c.identifier, name=c.name) not in observed_groups
    ]
    never_observed.sort(key=lambda c: (c["kind"], c["name"], c["identifier"], c["declared_uuid"]))

    # Declared AND observed, but never assessed: the case this manifest exists for.
    # EVERY observed row under a declared identity, not one of them. When two rows
    # answer to one identity and only one was assessed, the declared component was
    # not assessed as a whole -- and which row a dict kept decided the verdict.
    declared_unassessed = [
        _entity(asset)
        for asset in unassessed
        if component_key(asset.kind, identifier=asset.identifier, name=asset.name) in declared_groups
    ]
    declared_unassessed.sort(key=lambda c: (c["kind"], c["name"], c["identifier"], c["asset_uuid"]))

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

    checks = _checks_section(deployment)

    # A check the engine never ran holds the decision exactly as a component
    # nobody assessed does, and for the same reason: the report's silence on it
    # is not a result. It joins the critical path rather than sitting beside it,
    # because a gap that only appears in a panel is a gap nothing acts on.
    critical_gap = bool(
        never_observed or declared_unassessed or high_risk_unassessed
        or (checks["reported"] and not checks["complete"])
    )

    if checks["reported"] and not checks["complete"]:
        # Checked before the declaration test, and this is the one ordering
        # decision in the function. The check axis carries its own baseline -- the
        # engine's list of what it can run -- so a check that did not run is a
        # measured shortfall even when the customer declared nothing. Reading that
        # as UNDECLARED would file a known gap under "we have no way to tell".
        verdict = INCOMPLETE
    elif not declared:
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
        # The second axis, whole, so a reader can see which kind of gap this is.
        "checks": checks,
        "never_observed": never_observed,
        "declared_but_unassessed": declared_unassessed,
        "high_risk_unassessed": high_risk_unassessed,
        "unassessed": unassessed_entities,
        "summary": (
            f"Expected {len(declared)} / Observed {len(assets)} / "
            f"Assessed {len(assessed)}"
            + (f" / Checks {checks['performed']}/{checks['total']}"
               if checks["reported"] else "")
            + f" -> {verdict.upper()}"
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
    # COMPLETE already carries both axes: `coverage_manifest` cannot return it
    # while a reported check fell short. Re-testing the check axis here would read
    # as a second safeguard and be unreachable code, so the invariant is pinned as
    # a property of the verdict instead -- see
    # test_the_verdict_is_never_complete_while_a_check_fell_short.
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
    # The check axis first, and deliberately before the declaration test. A scan
    # that did not run a check has fallen short of a list the engine brought with
    # it, so this is the one coverage cap that applies to a deployment whose
    # architecture nobody declared -- which, in practice, is most of them early on.
    if checks_gap(deployment):
        return Deployment.Decision.AUDIT_INCOMPLETE
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
