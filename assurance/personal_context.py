"""Personal Context Exposure — what personal data the deployment holds, where it
lives, and who can reach it (Phase 3.5, data & context).

The first of the four "data & context" assessments. It answers a question a
privacy or data-protection reviewer asks first: *what user/customer/personal data
does this AI system hold, in which components, and which identities can reach
it?* Like its siblings it invents nothing — it reconciles signals that already
exist:

- **Data-bearing components** are the graph's data stores and vector/RAG
  retrieval stores (the ``_DATA_KINDS`` :mod:`assurance.access` already reasons
  over) — the places personal data comes to rest.
- **Data-sensitivity signals** are read from each component's recorded
  ``metadata`` (a discovery-declared ``data_classification`` / ``data_categories``
  / ``pii`` signal). A component whose metadata attests personal categories bears
  **personal** data at ``configuration_verified`` strength; a provider assertion
  can raise or evidence it at its own class. A component with **no** such signal
  reads **unknown** — never "no PII". An unclassified data store is a gap
  (personal-data exposure cannot be ruled out), not a clean bill.
- **Who can reach it** reuses :func:`assurance.access.assess_effective_access`
  wholesale — the evidenced principal→component reach graph. A store's readers are
  exactly the principals whose evidenced reach path lands on it; no path is
  re-derived here, so the no-invented-reach guarantee is inherited.
- **Boundary crossing** reuses :func:`assurance.boundary.assess_boundary` — a
  personal-data store that is itself a shadow (unmanaged) destination, or whose
  provider flow is a boundary violation, is personal data leaving the approved
  boundary.

It is honest in the same way its siblings are:

- Nothing reads "secure" / "compliant" / "safe". An unknown classification reads
  unknown; an unevidenced control is a gap, never a pass.
- Personal data reachable by a **shadow** or **over-broad** principal, reachable
  by a **privileged** principal, or **crossing the approved boundary**, is a gap
  surfaced with its risk, not smoothed away.
- No sensitive **values** are emitted — only the presence of a category and the
  lineage (which component, which reader), never a datum itself.

Computed on read (a pure function of the stored graph), like
:func:`assurance.boundary.assess_boundary` — no new record, no migration, no
timestamp in the payload. Prefetch ``assets__provider__assertions`` and
``select_related('data_boundary')`` on the caller side. Nothing here reaches the
network.
"""

from __future__ import annotations

import re

from .access import (
    PRIVILEGE_HIGH,
    assess_effective_access,
)
from .boundary import assess_boundary
from .capability import (
    RISK_BASELINE,
    RISK_ELEVATED,
    RISK_HIGH,
    _MANAGED,
    _RISK_ORDER,
    _RISK_RAISED,
    _max_risk,
)
from .models import Asset, EvidenceClass

# The kinds that bring personal data to rest: a backing data store and a
# vector / RAG retrieval store. Same set :mod:`assurance.access` treats as data
# targets — the components a "who can reach this data" question is about.
DATA_BEARING_KINDS = {Asset.Kind.DATA_STORE, Asset.Kind.VECTOR_DB}

# The metadata keys discovery may record a component's data classification under.
# All optional and additive — a component that carries none reads *unknown*, never
# "no PII".
_CLASSIFICATION_KEYS = ("data_classification", "data_categories", "classification", "data")

_WORD_RE = re.compile(r"[a-z0-9]+")

# Tokens that attest the component holds personal / user / customer data. Matched
# as whole words against the declared classification signal, so an incidental
# substring never invents a personal-data claim.
_PERSONAL_TOKENS = frozenset(
    {
        "pii",
        "personal",
        "person",
        "customer",
        "user",
        "profile",
        "identity",
        "contact",
        "email",
        "phone",
        "address",
        "name",
        "ssn",
        "dob",
        "health",
        "phi",
        "medical",
        "financial",
        "payment",
        "biometric",
        "sensitive",
        "gdpr",
        "ccpa",
    }
)

# A privilege that makes a reader concerning even without shadow/over-broad status.
_PRIVILEGED = PRIVILEGE_HIGH


def _tokens(value) -> set[str]:
    """The lowercase word tokens of a declared classification signal, whether it is
    a string, a list of strings, or nested — read defensively so a stray shape
    never raises."""
    out: set[str] = set()
    if isinstance(value, str):
        out.update(_WORD_RE.findall(value.lower()))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            out |= _tokens(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            out |= _tokens(k)
            out |= _tokens(v)
    elif isinstance(value, bool):
        # A bare ``metadata["pii"] = True`` flag handled by the caller, not here.
        pass
    return out


def _sensitivity(asset) -> tuple[str, list[str], str]:
    """This component's data sensitivity, the signals that evidenced it, and the
    evidence class behind the determination.

    Returns ``("personal", [signals], evidence_class)`` when the recorded metadata
    attests personal categories, otherwise ``("unknown", [], "unknown")`` — an
    absent signal is honestly unknown, never "no PII"."""
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}

    # An explicit boolean PII flag is the clearest declared signal.
    if metadata.get("pii") is True or metadata.get("personal_data") is True:
        return "personal", ["metadata pii flag"], EvidenceClass.CONFIGURATION_VERIFIED.value

    matched: set[str] = set()
    for key in _CLASSIFICATION_KEYS:
        if key in metadata:
            matched |= _tokens(metadata[key]) & _PERSONAL_TOKENS
    if matched:
        signals = sorted(f"data classification '{tok}'" for tok in matched)
        return "personal", signals, EvidenceClass.CONFIGURATION_VERIFIED.value
    return "unknown", [], EvidenceClass.UNKNOWN.value


def _reach_index(access_result: dict) -> dict[str, list[dict]]:
    """Index the evidenced effective-access reach graph by the stable *uuid* of the
    concrete component reached: ``{target_uuid: [reader, ...]}``. Keying on the uuid
    (not the non-unique asset name) keeps two components sharing a name from
    cross-contaminating each other's reader list. A reader records the principal
    that reaches the component and the reach's risk/via — read only from what
    :func:`assurance.access.assess_effective_access` already attested."""
    index: dict[str, list[dict]] = {}
    for principal in access_result["principals"]:
        for reach in principal["effective_reach"]:
            # Only concrete-component reaches name a data store; a capability-power
            # reach targets a power, not a store.
            if reach["target_kind"] == "capability":
                continue
            index.setdefault(reach["target_uuid"], []).append(
                {
                    "principal": principal["name"],
                    "principal_kind": principal["kind"],
                    "principal_kind_label": principal["kind_label"],
                    "privilege_level": principal["privilege_level"],
                    "shadow": principal["shadow"],
                    "over_broad": principal["over_broad"],
                    "risk": reach["risk"],
                    "via": reach["via"],
                }
            )
    return index


def _boundary_index(boundary_result: dict) -> tuple[set[str], set[int]]:
    """From the data-boundary assessment: the set of shadow-destination asset names
    (unmanaged sinks outside any approved boundary) and the set of provider ids
    whose flow is a boundary *violation*. Used to tell when a personal-data store
    is personal data leaving the approved boundary."""
    shadow_names = {d["asset_name"] for d in boundary_result.get("shadow_destinations", [])}
    violation_providers = {
        f["provider_uuid"] for f in boundary_result.get("flows", []) if f["status"] == "violation"
    }
    return shadow_names, violation_providers


def _store_dict(asset, sensitivity, signals, evidence_class, readers, shadow_names, violation_providers) -> dict:
    """Assemble one personal-context store: where it is, what it bears, who can
    reach it (evidenced only), and its gaps. Pure — reads only what was passed."""
    managed = asset.classification in _MANAGED
    is_personal = sensitivity == "personal"

    # Base risk: a data store at rest is baseline; an unmanaged one is raised a band
    # (an ungoverned personal-data store is worse than a governed one).
    base_risk = RISK_BASELINE if managed else _RISK_RAISED[RISK_BASELINE]

    readers = sorted(readers, key=lambda r: (_RISK_ORDER.index(r["risk"]), not r["shadow"], r["principal"]))

    gaps: list[dict] = []

    # Unknown classification on a data-bearing component: personal-data exposure
    # cannot be ruled out. Surfaced as a gap, never as "no PII".
    if sensitivity == "unknown":
        gaps.append(
            {
                "type": "unclassified",
                "risk": RISK_ELEVATED,
                "detail": "Data-bearing component with no recorded data classification — "
                "personal-data exposure cannot be ruled out.",
            }
        )

    shadow_readers = sorted({r["principal"] for r in readers if r["shadow"]})
    if shadow_readers:
        gaps.append(
            {
                "type": "reachable_by_shadow",
                "risk": RISK_HIGH,
                "detail": "Reachable by shadow (unmanaged) principals: " + ", ".join(shadow_readers),
                "principals": shadow_readers,
            }
        )

    over_broad_readers = sorted({r["principal"] for r in readers if r["over_broad"]})
    if over_broad_readers:
        gaps.append(
            {
                "type": "reachable_by_over_broad",
                "risk": RISK_HIGH,
                "detail": "Reachable by over-broad principals (data + execution + network reach): "
                + ", ".join(over_broad_readers),
                "principals": over_broad_readers,
            }
        )

    privileged_readers = sorted(
        {r["principal"] for r in readers if r["privilege_level"] == _PRIVILEGED}
    )
    if privileged_readers:
        gaps.append(
            {
                "type": "reachable_by_privileged",
                "risk": RISK_ELEVATED,
                "detail": "Reachable by high-privilege principals: " + ", ".join(privileged_readers),
                "principals": privileged_readers,
            }
        )

    # Crossing the approved boundary: the store is itself a shadow destination, or
    # its provider flow is a boundary violation.
    crossing_reasons: list[str] = []
    if asset.name in shadow_names:
        crossing_reasons.append("an unmanaged (shadow) data destination outside any approved boundary")
    if asset.provider_id is not None and getattr(asset, "provider", None) is not None:
        if str(asset.provider.uuid) in violation_providers:
            crossing_reasons.append("behind a provider flow that violates the approved data boundary")
    if crossing_reasons:
        gaps.append(
            {
                "type": "crosses_boundary",
                "risk": RISK_HIGH,
                "detail": "Personal data leaving the approved boundary: " + "; ".join(crossing_reasons),
            }
        )

    gaps.sort(key=lambda g: (_RISK_ORDER.index(g["risk"]), g["type"]))

    risk = base_risk
    for gap in gaps:
        risk = _max_risk(risk, gap["risk"])
    # A gap on a component of unknown sensitivity is real, but a *personal*-data
    # store carrying the same gap is the more concerning reading; nothing lowers a
    # gap's own risk here — risk is the worst of base and any gap.

    return {
        "asset_name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "identifier": asset.identifier,
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        "managed": managed,
        "provider_name": asset.provider.name if getattr(asset, "provider", None) else None,
        "data_sensitivity": sensitivity,
        "personal_data": is_personal,
        "signals": signals,
        "evidence_class": evidence_class,
        "evidence_class_label": EvidenceClass(evidence_class).label,
        "reachable_by": readers,
        "reader_count": len(readers),
        "gaps": gaps,
        "risk": risk,
    }


def assess_personal_context(deployment) -> dict:
    """The full personal-context exposure assessment for a deployment: every
    data-bearing component, what personal data it evidences (or an honest unknown),
    which principals can reach it (evidenced reach only), the gaps, and an honest
    roll-up.

    Prefetch ``assets__provider__assertions`` and ``select_related('data_boundary')``
    on the caller side. Pure and side-effect-free — a computed view of the stored
    graph, never a stored record."""
    access_result = assess_effective_access(deployment)
    boundary_result = assess_boundary(deployment)
    reach_index = _reach_index(access_result)
    shadow_names, violation_providers = _boundary_index(boundary_result)

    stores: list[dict] = []
    for asset in deployment.assets.all():
        if asset.kind not in DATA_BEARING_KINDS:
            continue
        sensitivity, signals, evidence_class = _sensitivity(asset)
        readers = reach_index.get(str(asset.uuid), [])
        stores.append(
            _store_dict(
                asset,
                sensitivity,
                signals,
                evidence_class,
                readers,
                shadow_names,
                violation_providers,
            )
        )

    # Most-concerning first: worst risk, personal before unknown within a band,
    # then name for a stable, deterministic order.
    stores.sort(
        key=lambda s: (_RISK_ORDER.index(s["risk"]), not s["personal_data"], s["asset_name"])
    )

    # A flat, deduplicated gap roll-up for a reader who wants the concerns only.
    gap_rollup: list[dict] = []
    for store in stores:
        for gap in store["gaps"]:
            gap_rollup.append({**gap, "asset_name": store["asset_name"]})
    gap_rollup.sort(key=lambda g: (_RISK_ORDER.index(g["risk"]), g["type"], g["asset_name"]))

    worst_risk = None
    for store in stores:
        worst_risk = store["risk"] if worst_risk is None else _max_risk(worst_risk, store["risk"])

    summary = {
        "data_bearing_components": len(stores),
        "personal_data_components": sum(1 for s in stores if s["personal_data"]),
        "unclassified_components": sum(1 for s in stores if s["data_sensitivity"] == "unknown"),
        "reachable_by_shadow": sum(
            1 for s in stores for g in s["gaps"] if g["type"] == "reachable_by_shadow"
        ),
        "reachable_by_over_broad": sum(
            1 for s in stores for g in s["gaps"] if g["type"] == "reachable_by_over_broad"
        ),
        "crossing_boundary": sum(
            1 for s in stores for g in s["gaps"] if g["type"] == "crosses_boundary"
        ),
        "gaps": len(gap_rollup),
    # The reach graph both of these are built on. An unplaceable reference
    # means part of that graph could not be found, so this report is what the
    # graph we HAVE supports -- not a statement about the whole system. It is
    # carried through rather than re-derived: one source for the gap, the same
    # shape in every report that stands on it.
        "unresolved_references": len(access_result["unresolved"]),
        "worst_risk": worst_risk,
    }

    return {
        "stores": stores,
        "gaps": gap_rollup,
        "unresolved": access_result["unresolved"],
        "summary": summary,
    }
