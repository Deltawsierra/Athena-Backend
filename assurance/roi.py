"""Executive summary — the assurance graph rolled up for a leadership reader.

The executive-facing layer of the assurance spine. It translates the graph the
rest of this package computes — assets, findings, evidence, remediation, the
six-state decision, and the sibling assessments — into a compact roll-up an
executive or board reader can act on, built **only** from real counts and real
ratios of real counts.

What it is, and what it refuses to be:

- **Value is posture, coverage and counts — never money.** Following the rule
  :mod:`assurance.business_impact` establishes, this module emits **no dollar
  figure, no ROI amount, no realized-loss number, and no fabricated percentage.**
  Every ratio here is a true ratio of two real counts (classified assets over
  total assets, resolved findings over total findings), and every band is an
  ordinal derived from the graph. A reader who wants an invented number will not
  find one — turning the graph into a currency figure would be a fabrication, not
  a summary.
- **Honest about what is unknown.** Unknown and shadow assets lower coverage
  rather than being hidden; unverified findings are counted as such; a resolved
  *remediation* state is reported as a process claim, never as the security
  disposition (a finding is securely closed only through ``status``, which the
  decision already reflects). Nothing here says a system is secure.
- **A roll-up of assessments that already exist.** The compliance, business-impact,
  capability, boundary and vendor assessments are reused (lazily imported to avoid
  the import cycle :mod:`assurance.receipt` also sidesteps), each contributing its
  own honest headline, so the summary never re-derives a conclusion a sibling
  module already owns.

Computed on read (a pure function of the stored graph), like its siblings — no new
record, no migration, no timestamp in the returned identity content. Prefetch
``findings__evidence`` and ``assets__provider__assertions`` and select_related
``data_boundary`` on the caller side to keep it query-light.
"""

from __future__ import annotations

from .graph_refs import in_graph
from .capability import RISK_BASELINE, RISK_ELEVATED, RISK_HIGH
from .models import (
    RESOLVED_FINDING_STATUSES,
    SEVERITY_ORDER,
    Asset,
    EvidenceClass,
    Finding,
    evidence_strength,
    severity_rank,
)
from .governance import GOVERNED, is_shadow

# Findings in these states are resolved — no longer active. Mirrors
# ``assurance.decision`` and the sibling assessments so every view agrees on what
# "active" means.
# The one definition lives in ``assurance.models`` beside the statuses themselves.
# Seven modules each kept their own copy of this set, and every one of their
# comments said it "mirrors" the others so every view would agree on what "active"
# means -- which is precisely the arrangement that lets them stop agreeing. Adding
# a status meant editing eight places and silently disagreeing if you missed one.
_RESOLVED_STATUSES = RESOLVED_FINDING_STATUSES

# A component is *classified* (covered by discovery) unless it is unknown or an
# unmanaged shadow — the two coverage gaps. Managed is the narrower governed set.
# The single definition, not a fourth private copy of it.
_MANAGED = GOVERNED
# A DIFFERENT axis from governance, deliberately. This asks "has anybody
# classified this at all", which is why `high_risk` and `retired` count as
# classified here while `is_shadow` calls them ungoverned: somebody looked at
# them and said something, and what they said was bad. Coverage and governance
# are two questions; collapsing them is how three predicates became three
# answers. See assurance.governance.
_COVERAGE_GAP_CLASSIFICATIONS = {Asset.Classification.UNKNOWN, Asset.Classification.UNMANAGED}

# Evidence classes that mean "genuinely not known", counted as unverified — the
# same pair the decision uses for NEEDS_MORE_EVIDENCE.
_UNVERIFIED = frozenset({EvidenceClass.UNKNOWN, EvidenceClass.NOT_DOCUMENTED})
_VENDOR_ASSERTED_RANK = evidence_strength(EvidenceClass.VENDOR_ASSERTED)

# Remediation states that are not open work: RESOLVED (a human called the work
# done — a process claim) and WONT_FIX (closed out). Everything else is open.
_REMEDIATION_CLOSED = frozenset(
    {Finding.RemediationState.RESOLVED, Finding.RemediationState.WONT_FIX}
)

# Ordinal assurance-maturity band — a qualitative read of how well-evidenced the
# assurance picture is, derived only from real coverage and evidence ratios. It
# describes evidence coverage, never that a system is secure. Best → weakest.
MATURITY_WELL_EVIDENCED = "well_evidenced"
MATURITY_PARTIALLY_EVIDENCED = "partially_evidenced"
MATURITY_SPARSELY_EVIDENCED = "sparsely_evidenced"


def _ratio(numerator: int, denominator: int) -> float | None:
    """A true ratio of two real counts, rounded, or None when the denominator is
    zero. Never a fabricated percentage — None means "no basis to compute", not 0%."""
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def _asset_coverage(deployment) -> dict:
    """Asset coverage: how much of the discovered component graph is classified,
    versus unknown or shadow (unmanaged). Real counts and true ratios only."""
    by_classification: dict[str, int] = {}
    total = classified = managed = unknown = shadow = high_risk = 0
    for asset in in_graph(deployment.assets.all()):
        total += 1
        by_classification[asset.classification] = by_classification.get(asset.classification, 0) + 1
        if asset.classification not in _COVERAGE_GAP_CLASSIFICATIONS:
            classified += 1
        if asset.classification in _MANAGED:
            managed += 1
        if asset.classification == Asset.Classification.UNKNOWN:
            unknown += 1
        if is_shadow(asset.classification):
            shadow += 1
        if asset.classification == Asset.Classification.HIGH_RISK:
            high_risk += 1
    return {
        "total_assets": total,
        "classified": classified,
        "managed": managed,
        "unknown": unknown,
        "shadow": shadow,
        "high_risk": high_risk,
        "by_classification": by_classification,
        "coverage_ratio": _ratio(classified, total),
        "managed_ratio": _ratio(managed, total),
    }


def _evidence_and_findings(deployment) -> tuple[dict, dict, int]:
    """Evidence-strength distribution over findings and the finding posture by
    severity, read from the prefetched graph. Returns (evidence, findings,
    independently_evidenced_count)."""
    by_class: dict[str, int] = {}
    active_by_severity: dict[str, int] = {}
    total = active = resolved = independently = unverified = 0
    worst_active_rank = -1

    for finding in deployment.findings.all():
        total += 1
        # The finding's honest evidence class is the weakest behind it.
        ec = finding.evidence_class
        by_class[ec] = by_class.get(ec, 0) + 1
        if evidence_strength(ec) < _VENDOR_ASSERTED_RANK:
            independently += 1
        if ec in _UNVERIFIED:
            unverified += 1

        if finding.status in _RESOLVED_STATUSES:
            resolved += 1
            continue
        active += 1
        active_by_severity[finding.severity] = active_by_severity.get(finding.severity, 0) + 1
        rank = severity_rank(finding.severity)
        if rank > worst_active_rank:
            worst_active_rank = rank

    evidence = {
        "by_class": by_class,
        "independently_evidenced": independently,
        "unverified": unverified,
        "finding_count": total,
    }
    findings = {
        "total": total,
        "active": active,
        "resolved": resolved,
        "active_by_severity": active_by_severity,
        "worst_active_severity": SEVERITY_ORDER[worst_active_rank] if worst_active_rank >= 0 else None,
    }
    return evidence, findings, independently


def _remediation(deployment) -> dict:
    """Remediation velocity from the workflow: open vs resolved counts, the state
    distribution, the distinct states the deployment's findings have reached, and
    how many attributed events are on record. ``resolution_ratio`` is a process
    claim (someone called the work done), never the security disposition."""
    by_state: dict[str, int] = {}
    open_count = resolved_count = wont_fix_count = event_count = 0
    states_reached: set[str] = set()
    total = 0
    for finding in deployment.findings.all():
        total += 1
        state = finding.remediation_state
        by_state[state] = by_state.get(state, 0) + 1
        if state == Finding.RemediationState.RESOLVED:
            resolved_count += 1
        elif state == Finding.RemediationState.WONT_FIX:
            wont_fix_count += 1
        if state not in _REMEDIATION_CLOSED:
            open_count += 1
        for event in finding.remediation_events.all():
            event_count += 1
            states_reached.add(event.to_state)
    return {
        "open": open_count,
        "resolved": resolved_count,
        "wont_fix": wont_fix_count,
        "by_state": by_state,
        "states_reached": sorted(states_reached),
        "event_count": event_count,
        # A process claim: resolved-in-workflow over all findings. Not a security
        # closure rate — a finding is securely closed only through ``status``.
        "resolution_ratio": _ratio(resolved_count, total),
    }


def _posture(worst_active_severity: str | None, shadow_assets: int) -> str:
    """The deployment's ordinal risk posture, reusing the capability module's
    risk-band vocabulary. An active high/critical finding is ``high``; a lesser
    active finding, or any shadow asset, is ``elevated``; otherwise ``baseline``.
    A concern signal, never a claim the system is secure."""
    rank = severity_rank(worst_active_severity) if worst_active_severity else -1
    if rank >= severity_rank("high"):
        posture = RISK_HIGH
    elif rank >= severity_rank("low"):
        posture = RISK_ELEVATED
    else:
        posture = RISK_BASELINE
    if shadow_assets and posture == RISK_BASELINE:
        posture = RISK_ELEVATED
    return posture


def _maturity(coverage_ratio: float | None, independent_ratio: float | None, total_assets: int) -> str:
    """A qualitative assurance-maturity band from real coverage: how much of the
    graph is classified and how much of what is found is independently evidenced.
    The weaker of the two signals sets the floor — an honest read never rounds up
    past its softest input. Describes evidence coverage, never security."""
    if total_assets == 0:
        # Nothing discovered to evidence — the most honest read is the weakest band.
        return MATURITY_SPARSELY_EVIDENCED
    cov = coverage_ratio if coverage_ratio is not None else 0.0
    ind = independent_ratio if independent_ratio is not None else 0.0
    signal = min(cov, ind)
    if signal >= 0.8:
        return MATURITY_WELL_EVIDENCED
    if signal >= 0.4:
        return MATURITY_PARTIALLY_EVIDENCED
    return MATURITY_SPARSELY_EVIDENCED


def _assessment_headlines(deployment) -> dict:
    """A one-line honest headline from each sibling assessment, so the executive
    summary rolls up the assessments rather than re-deriving them. Lazily imported
    to avoid the import cycle the receipt module also sidesteps."""
    from .boundary import assess_boundary
    from .business_impact import build_business_impact
    from .capability import assess_capabilities
    from .compliance import build_compliance_map
    from .vendor import assess_vendors

    compliance = build_compliance_map(deployment)["summary"]
    impact = build_business_impact(deployment)["summary"]
    capabilities = assess_capabilities(deployment)["summary"]
    boundary = assess_boundary(deployment)
    vendors = assess_vendors(deployment)["summary"]

    return {
        "compliance": {
            "controls_with_active_findings": compliance["controls_with_active_findings"],
            "worst_severity": compliance["worst_severity"],
        },
        "business_impact": {
            "dimensions_with_active_exposure": impact["dimensions_with_active_exposure"],
            "worst_exposure_band": impact["worst_exposure_band"],
            # Whose impact: how many accountable owners carry active exposure, and
            # how many findings are unattributed (a gap, not zero impact).
            "owners_with_active_exposure": impact["owners_with_active_exposure"],
            "findings_without_owner": impact["findings_without_owner"],
        },
        "capabilities": {
            "high_risk": capabilities["high_risk"],
            "shadow": capabilities["shadow"],
        },
        "boundary": {
            "declared": boundary["declared"],
            "violations": boundary["summary"]["violations"],
            "unknowns": boundary["summary"]["unknowns"],
            "shadow_destinations": boundary["summary"]["shadow_destinations"],
        },
        "vendors": {
            "vendors": vendors["vendors"],
            "gaps": vendors["gaps"],
            "worst_posture_band": vendors["worst_posture_band"],
            "independently_evidenced": vendors["independently_evidenced"],
            "vendor_asserted": vendors["vendor_asserted"],
        },
    }


def build_executive_summary(deployment) -> dict:
    """The executive-facing assurance roll-up for a deployment: asset coverage,
    evidence-strength distribution, finding posture by severity, remediation
    velocity, the standing six-state decision, an ordinal risk posture, a
    qualitative assurance-maturity band, and a headline from each sibling
    assessment. Prefetch ``findings__evidence`` and ``assets__provider__assertions``
    and select_related ``data_boundary`` on the caller side. Pure and
    side-effect-free, deterministic, no timestamp.

    Every value is a real count, a true ratio of real counts, or an ordinal band
    derived from the graph. There is **no dollar figure, no ROI amount, and no
    realized-loss number** anywhere in the output, by design — see the module
    docstring. Nothing here claims the system is secure."""
    coverage = _asset_coverage(deployment)
    evidence, findings, independently = _evidence_and_findings(deployment)
    remediation = _remediation(deployment)

    independent_ratio = _ratio(independently, evidence["finding_count"])
    posture = _posture(findings["worst_active_severity"], coverage["shadow"])
    maturity = _maturity(coverage["coverage_ratio"], independent_ratio, coverage["total_assets"])

    return {
        "system": {
            "name": deployment.name,
            "uuid": str(deployment.uuid),
            "environment": deployment.environment,
            "environment_label": deployment.get_environment_display(),
        },
        # The standing six-state decision, None-safe: an unassessed deployment has
        # no decision, and an absent decision is never read as "ready".
        "decision": {
            "decision": deployment.decision,
            "decision_label": deployment.get_decision_display() if deployment.decision else None,
        },
        "asset_coverage": coverage,
        "evidence": evidence,
        "findings": findings,
        "remediation": remediation,
        "assessments": _assessment_headlines(deployment),
        "posture": posture,
        "assurance_maturity": maturity,
        "summary": {
            "total_assets": coverage["total_assets"],
            "coverage_ratio": coverage["coverage_ratio"],
            "shadow_assets": coverage["shadow"],
            "total_findings": findings["total"],
            "active_findings": findings["active"],
            "resolved_findings": findings["resolved"],
            "worst_active_severity": findings["worst_active_severity"],
            "open_remediation": remediation["open"],
            "resolved_remediation": remediation["resolved"],
            "decision": deployment.decision,
            "posture": posture,
            "assurance_maturity": maturity,
        },
    }
