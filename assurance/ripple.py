"""Ripple Effect — blast-radius assessment (Phase 2.5).

The roadmap frames this view precisely: **"Ripple Effect — a *few well-supported*
downstream consequences."** Not a speculative full cascade. Before you can reason
about how far a compromise spreads you need the ground truth of who can touch what
(:func:`assurance.access.assess_effective_access`, Phase 3.1) and where data leaves
the approved boundary (:func:`assurance.boundary.assess_boundary`, Phase 1.4). This
module reads *only* those — it re-derives no reachability of its own — and answers
one question honestly: for each origin worth tracing, what can a compromise of it
reach downstream, and along which evidenced path.

An **origin** worth tracing is either:

- an **active** (unresolved) high/critical finding tied to a component (its
  ``asset``) — a live weakness at a concrete point in the graph; or
- a **privileged or high-risk principal** from the effective-access assessment —
  an identity that already wields sensitive power or reads at risk high.

For each origin the **blast radius** is what a compromise of it can reach
*downstream*, read off the effective-access reach graph: every evidenced reach
path is sliced at the origin node, and only the portion beyond it is a downstream
consequence. Because the paths come from :mod:`assurance.access`, the honesty
guarantee is inherited wholesale — a hop is only ever traversed where a declared
edge attests it, so a consequence is never invented for a hop the graph lacks.
Boundary data destinations (:mod:`assurance.boundary`) enrich a consequence whose
target is a destination that crosses the approved boundary.

Each consequence is one concrete, **potential**, evidence-based downstream effect:
what a compromise *could* do (data exposure, code execution, lateral movement,
external egress, a financial action), the target it reaches, the evidenced via-path
that supports it, its risk band, and the basis that evidences it.

It is honest in the same way its siblings are, and enforces these invariants:

- Every consequence is **evidence-based and potential** — tied to a declared path,
  phrased as what a compromise *could* do, never a realized harm, never a cascade
  the graph does not attest, and never a monetary figure.
- **"A few well-supported."** Consequences are ranked by risk and bounded (a cap
  per origin and overall), so the output stays the well-supported core, not an
  exhaustive speculative tree. The full evidenced count is reported so the bounding
  is visible, not hidden.
- It never claims the system is safe or a blast radius is contained or mitigated.
  An origin with no evidenced downstream reach reads honestly as **"no evidenced
  downstream reach"**, not as safe.
- Deterministic (same graph → same output), pure, and side-effect-free.

Computed on read (a pure function of the stored graph), like
:func:`assurance.access.assess_effective_access` and
:func:`assurance.boundary.assess_boundary` — no new record, no migration, no
timestamp in the assessment. Prefetch ``assets__provider__assertions`` and
``findings__asset`` on the caller side to keep it query-light. Nothing here reaches
the network.
"""

from __future__ import annotations

from .access import assess_effective_access
from .boundary import assess_boundary
from .capability import (
    RISK_BASELINE,
    RISK_HIGH,
    _RISK_ORDER,
    _max_risk,
)
from .models import SEVERITY_HIGH, Asset, Finding, severity_rank

# Findings in these states are resolved — no longer a live weakness, so never an
# active origin. Mirrors ``assurance.decision`` / ``assurance.business_impact`` so
# every view agrees on what "active" means.
_RESOLVED_STATUSES = frozenset(
    {Finding.Status.CLOSED, Finding.Status.ACCEPTED, Finding.Status.FALSE_POSITIVE}
)

# ---------------------------------------------------------------------------
# Consequence categories — the *kinds* of downstream effect a compromise could
# have. Each is a potential effect, never a realized one.
# ---------------------------------------------------------------------------

CATEGORY_DATA_EXPOSURE = "data_exposure"
CATEGORY_CODE_EXECUTION = "code_execution"
CATEGORY_LATERAL_MOVEMENT = "lateral_movement"
CATEGORY_EXTERNAL_EGRESS = "external_egress"
CATEGORY_FINANCIAL_ACTION = "financial_action"

_CATEGORY_LABELS = {
    CATEGORY_DATA_EXPOSURE: "Data exposure",
    CATEGORY_CODE_EXECUTION: "Code execution",
    CATEGORY_LATERAL_MOVEMENT: "Lateral movement",
    CATEGORY_EXTERNAL_EGRESS: "External egress",
    CATEGORY_FINANCIAL_ACTION: "Financial action",
}
# A stable category order for deterministic sort tie-breaks.
_CATEGORY_ORDER = {
    key: i
    for i, key in enumerate(
        (
            CATEGORY_CODE_EXECUTION,
            CATEGORY_FINANCIAL_ACTION,
            CATEGORY_DATA_EXPOSURE,
            CATEGORY_EXTERNAL_EGRESS,
            CATEGORY_LATERAL_MOVEMENT,
        )
    )
}

# A sensitive capability-power (from ``assurance.capability``'s declared-permission
# map) → the downstream-consequence category it evidences. A power not listed here
# still reaches its declaring component as lateral movement.
_POWER_CATEGORY = {
    "code_execution": CATEGORY_CODE_EXECUTION,
    "destructive_action": CATEGORY_CODE_EXECUTION,
    "financial_action": CATEGORY_FINANCIAL_ACTION,
    "privileged_control": CATEGORY_LATERAL_MOVEMENT,
    "network_access": CATEGORY_EXTERNAL_EGRESS,
    "messaging": CATEGORY_EXTERNAL_EGRESS,
    "filesystem_access": CATEGORY_DATA_EXPOSURE,
    "data_query": CATEGORY_DATA_EXPOSURE,
}

# What each capability-power lets a compromise *potentially* do. Phrased as "could"
# — a potential effect, never a realized one.
_POWER_PHRASE = {
    "code_execution": "Could execute code or shell commands",
    "destructive_action": "Could perform destructive actions on data or resources",
    "financial_action": "Could initiate a financial transaction",
    "privileged_control": "Could exercise privileged or administrative control",
    "network_access": "Could make outbound network calls",
    "messaging": "Could send messages or email outbound",
    "filesystem_access": "Could read or write the filesystem",
    "data_query": "Could query a backing database",
}

# A concrete reached target → the category its kind evidences.
_KIND_CATEGORY = {
    Asset.Kind.DATA_STORE: CATEGORY_DATA_EXPOSURE,
    Asset.Kind.VECTOR_DB: CATEGORY_DATA_EXPOSURE,
    Asset.Kind.MCP_SERVER: CATEGORY_EXTERNAL_EGRESS,
    Asset.Kind.API: CATEGORY_EXTERNAL_EGRESS,
    Asset.Kind.GATEWAY: CATEGORY_EXTERNAL_EGRESS,
    Asset.Kind.SKILL: CATEGORY_CODE_EXECUTION,
}

# "A few well-supported": the bounds that keep the output the well-supported core
# rather than an exhaustive speculative tree. Deliberate, ordinal, not a threshold
# on any amount.
MAX_CONSEQUENCES_PER_ORIGIN = 3
MAX_CONSEQUENCES_TOTAL = 12


def _risk_index(risk: str) -> int:
    return _RISK_ORDER.index(risk)


def _category(entry: dict) -> str:
    """The downstream-consequence category a reach entry evidences: from the
    sensitive power for a capability-power reach, otherwise from the target's kind,
    defaulting to lateral movement for a plain component-to-component hop."""
    if entry["target_kind"] == "capability":
        return _POWER_CATEGORY.get(entry["capability"], CATEGORY_LATERAL_MOVEMENT)
    return _KIND_CATEGORY.get(entry["target_kind"], CATEGORY_LATERAL_MOVEMENT)


def _phrase(entry: dict, category: str) -> str:
    """The potential downstream effect, phrased as what a compromise *could* do —
    never a realized harm. A capability-power names the power; a concrete target
    names the component reached."""
    if entry["target_kind"] == "capability":
        return _POWER_PHRASE.get(entry["capability"], "Could exercise a reachable power")
    target = entry["target"]
    if category == CATEGORY_DATA_EXPOSURE:
        return f"Could read or exfiltrate data from {target}"
    if category == CATEGORY_EXTERNAL_EGRESS:
        return f"Could route data outbound through {target}"
    if category == CATEGORY_CODE_EXECUTION:
        return f"Could execute code by running {target}"
    return f"Could move laterally to {target}"


def _downstream_from(node_name: str, principals: list) -> list:
    """The evidenced downstream reach of a node, read off the effective-access
    graph. Every principal reach path is sliced at ``node_name``; only the portion
    *beyond* the node is downstream. A reach is included only when the node is not
    the last element of the path — a node reaching *itself* is not a consequence.

    Returns reach-entry dicts (as :func:`assurance.access.assess_effective_access`
    shapes them) with ``via`` rewritten to the sliced sub-path. Deduplicated by
    (target, sub-path, capability) so paths shared by several principals collapse to
    one, keeping the strongest risk. No hop is added — this only slices paths the
    access assessment already attested, inheriting its no-invented-reach guarantee.
    """
    best: dict[tuple, dict] = {}
    for principal in principals:
        for reach in principal["effective_reach"]:
            via = reach["via"]
            if node_name not in via:
                continue
            idx = via.index(node_name)
            # The node must have something beyond it in the path to be a downstream
            # consequence; a path that ends at the node reaches nothing further.
            if idx >= len(via) - 1:
                continue
            subpath = via[idx:]
            entry = dict(reach)
            entry["via"] = subpath
            key = (entry["target"], tuple(subpath), entry["capability"])
            existing = best.get(key)
            if existing is None or _risk_index(entry["risk"]) < _risk_index(existing["risk"]):
                best[key] = entry
    return list(best.values())


def _consequence(origin: dict, entry: dict, boundary_note: str | None) -> dict:
    """One downstream consequence: a potential, evidence-based effect a compromise
    of the origin could have, tied to the evidenced via-path that supports it."""
    category = _category(entry)
    is_power = entry["target_kind"] == "capability"
    # The concrete component the effect lands on: the reached asset, or, for a
    # capability-power, the component that declares the permission (the node just
    # before the ``permission '...'`` marker in the path).
    target = entry["target"] if not is_power else (entry["via"][-2] if len(entry["via"]) >= 2 else entry["via"][-1])

    basis: list[str] = []
    if is_power:
        basis.append("declared permission on a component reachable from the origin")
    else:
        basis.append("declared reach path through the asset graph (invoke/connect edges)")
    if boundary_note:
        basis.append(boundary_note)

    return {
        "origin": origin["origin"],
        "origin_key": origin["key"],
        "consequence": _phrase(entry, category),
        "category": category,
        "category_label": _CATEGORY_LABELS[category],
        "target": target,
        "targets": sorted({target}),
        "via": entry["via"],
        "risk": entry["risk"],
        # Potential, not realized — stated on every row so the discipline is on the
        # wire, not only in the docstring.
        "potential": True,
        "evidence_basis": basis,
    }


def _consequence_sort_key(c: dict):
    """Rank most-concerning first: by risk band, then a stable category order, then
    target and path for a deterministic tie-break."""
    return (
        _risk_index(c["risk"]),
        _CATEGORY_ORDER[c["category"]],
        c["target"],
        tuple(c["via"]),
    )


def assess_ripple(deployment) -> dict:
    """The Ripple Effect (blast-radius) assessment for a deployment: the origins
    worth tracing, a bounded and ranked list of their evidenced downstream
    consequences, and an honest roll-up.

    Reads only :func:`assurance.access.assess_effective_access` and
    :func:`assurance.boundary.assess_boundary` — it re-derives no reachability of
    its own, so it inherits their no-invented-reach guarantee. Prefetch
    ``assets__provider__assertions`` and ``findings__asset`` on the caller side.
    Pure and side-effect-free, deterministic, no timestamp. See the module
    docstring for the honesty discipline."""
    access = assess_effective_access(deployment)
    principals = access["principals"]
    boundary = assess_boundary(deployment)

    # Boundary destinations that cross the approved boundary — used to enrich a
    # consequence whose target is one of them, giving the boundary assessment a
    # concrete role in the basis.
    shadow_dests = {d["asset_name"] for d in boundary["shadow_destinations"]}
    flow_violation: set[str] = set()
    for flow in boundary["flows"]:
        if flow["status"] == "violation":
            flow_violation.update(flow["assets"])

    def boundary_note(target_name: str) -> str | None:
        if target_name in shadow_dests:
            return "target is an unmanaged data destination outside the approved boundary"
        if target_name in flow_violation:
            return "target's data flow is a declared boundary violation"
        return None

    # --- Origins worth tracing, keyed by the graph node so a node that is both a
    # finding site and a principal is one origin with both reasons, never two. ---
    origins: dict[str, dict] = {}

    def ensure(name: str) -> dict:
        origin = origins.get(name)
        if origin is None:
            origin = {
                "key": f"node:{name}",
                "origin": name,
                "origin_types": [],
                "reasons": [],
                "risk": RISK_BASELINE,
                "findings": [],
            }
            origins[name] = origin
        return origin

    # Principal origins: a privileged identity, or one that reads at risk high.
    for principal in principals:
        if not (principal["privileged"] or principal["risk"] == RISK_HIGH):
            continue
        origin = ensure(principal["name"])
        if "principal" not in origin["origin_types"]:
            origin["origin_types"].append("principal")
        origin["key"] = principal["key"]
        origin["principal_kind"] = principal["kind"]
        origin["principal_kind_label"] = principal["kind_label"]
        origin["privilege_level"] = principal["privilege_level"]
        origin["risk"] = _max_risk(origin["risk"], principal["risk"])
        why = "privileged principal" if principal["privileged"] else "high-risk principal"
        origin["reasons"].append(why)

    # Finding origins: an active high/critical finding tied to a component.
    high_rank = severity_rank(SEVERITY_HIGH)
    for finding in deployment.findings.all():
        if finding.status in _RESOLVED_STATUSES:
            continue
        if severity_rank(finding.severity) < high_rank:
            continue
        if finding.asset_id is None:
            continue
        name = finding.asset.name
        origin = ensure(name)
        if "finding" not in origin["origin_types"]:
            origin["origin_types"].append("finding")
        origin["risk"] = _max_risk(origin["risk"], RISK_HIGH)
        origin["findings"].append(
            {
                "uuid": str(finding.uuid),
                "finding_type": finding.finding_type,
                "severity": finding.severity,
                "title": finding.title,
            }
        )
        origin["reasons"].append(f"active {finding.severity} finding: {finding.title}")

    # --- Blast radius per origin: the evidenced downstream reach, made into ranked,
    # bounded consequences. ---
    all_consequences: list[dict] = []
    evidenced_total = 0

    for origin in origins.values():
        downstream = _downstream_from(origin["origin"], principals)
        origin["evidenced_reach"] = bool(downstream)
        origin["consequence_count"] = len(downstream)
        origin["findings"].sort(key=lambda f: (f["finding_type"], f["title"], f["uuid"]))
        origin["reasons"] = sorted(set(origin["reasons"]))
        origin["origin_types"].sort()
        if not downstream:
            # Honest: no evidenced downstream reach is not "safe" or "contained".
            origin["note"] = "No evidenced downstream reach — no path the asset graph attests."
            continue
        evidenced_total += len(downstream)
        rows = [_consequence(origin, entry, boundary_note(entry["target"])) for entry in downstream]
        rows.sort(key=_consequence_sort_key)
        # "A few well-supported": keep the strongest per origin.
        all_consequences.extend(rows[:MAX_CONSEQUENCES_PER_ORIGIN])

    # Rank across origins and bound overall.
    all_consequences.sort(key=_consequence_sort_key)
    consequences = all_consequences[:MAX_CONSEQUENCES_TOTAL]

    origin_list = list(origins.values())
    origin_list.sort(key=lambda o: (_risk_index(o["risk"]), o["origin"]))

    by_category: dict[str, int] = {}
    for c in consequences:
        by_category[c["category"]] = by_category.get(c["category"], 0) + 1

    worst_risk = None
    for c in consequences:
        worst_risk = c["risk"] if worst_risk is None else _max_risk(worst_risk, c["risk"])

    origins_with_reach = sum(1 for o in origin_list if o["evidenced_reach"])

    summary = {
        "origins": len(origin_list),
        "origins_with_reach": origins_with_reach,
        "consequences": len(consequences),
        # The full evidenced count before bounding — the bounding is visible, not
        # hidden. ``consequences`` shows only the well-supported core.
        "evidenced_consequences": evidenced_total,
        "bounded": evidenced_total > len(consequences),
        "by_category": dict(sorted(by_category.items())),
        "worst_risk": worst_risk,
    }

    return {
        "origins": origin_list,
        "consequences": consequences,
        "summary": summary,
    }
