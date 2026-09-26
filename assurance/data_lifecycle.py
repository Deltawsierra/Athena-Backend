"""Data Lifecycle Review — the stages a deployment's data actually passes through,
and where a control for a stage is missing (Phase 3.5, data & context).

The lifecycle a data-protection reviewer walks: *collected → transmitted →
processed → logged → retained → reused → deleted*. For each stage this assessment
reports which components in the graph **evidence** the stage (and at what evidence
strength), and — the point of the exercise — the **gaps**: a stage with no
evidenced control. It invents nothing; it maps signals that already exist onto the
lifecycle:

- **Collected / transmitted / processed** are *flow* stages, evidenced by the
  presence of the components that carry data through them — a data store or vector
  store at rest (collected/retained), a model, gateway or MCP server data crosses
  the network to (transmitted), a model, agent or tool that acts on it (processed).
  A flow stage the graph does not populate reads **not evidenced**, never
  "compliant".
- **Logged / retained / reused / deleted** are *control* stages: a reviewer
  expects a control, and its absence is a gap. Logging is evidenced by an
  observability sink or a provider ``logging`` assertion; retention by a provider
  ``data_retention`` assertion or a durable store; reuse by a ``trains_on_data`` /
  ``subprocessors`` assertion; deletion by a retention/deletion assertion that
  names expiry or erasure. Each is carried at the **true evidence class** of the
  assertion behind it — a ``vendor_asserted`` retention window reads as
  vendor-asserted, never verified.

It is honest in the same way its siblings are:

- An unevidenced stage reads **"not evidenced"**, never "compliant" or "safe".
- It never asserts data *is* deleted or retained correctly without evidence — a
  control stage with no evidenced control is a **gap**, and a control evidenced
  only weakly (vendor-asserted / unknown) is a *weak* control, still a gap.
- Nothing here emits a data value; it reports stage → component lineage and the
  evidence strength only.

Computed on read (a pure function of the stored graph), like
:func:`assurance.boundary.assess_boundary` — no new record, no migration, no
timestamp in the payload. Prefetch ``assets__provider__assertions`` on the caller
side. Nothing here reaches the network.
"""

from __future__ import annotations

import re

from .graph_refs import in_graph
from .boundary import _negated
from .capability import (
    RISK_BASELINE,
    RISK_ELEVATED,
    RISK_HIGH,
    _RISK_ORDER,
    _max_risk,
)
from .models import Asset, EvidenceClass, Provider, ProviderAssertion, evidence_strength

# The lifecycle stages, in order.
STAGE_COLLECTED = "collected"
STAGE_TRANSMITTED = "transmitted"
STAGE_PROCESSED = "processed"
STAGE_LOGGED = "logged"
STAGE_RETAINED = "retained"
STAGE_REUSED = "reused"
STAGE_DELETED = "deleted"

STAGE_ORDER = (
    STAGE_COLLECTED,
    STAGE_TRANSMITTED,
    STAGE_PROCESSED,
    STAGE_LOGGED,
    STAGE_RETAINED,
    STAGE_REUSED,
    STAGE_DELETED,
)
STAGE_LABELS = {
    STAGE_COLLECTED: "Collected",
    STAGE_TRANSMITTED: "Transmitted",
    STAGE_PROCESSED: "Processed",
    STAGE_LOGGED: "Logged",
    STAGE_RETAINED: "Retained",
    STAGE_REUSED: "Reused",
    STAGE_DELETED: "Deleted",
}

# The *control* stages: a reviewer expects a control here, so an unevidenced one is
# a gap (elevated). The *flow* stages describe the data's journey; an unevidenced
# one is honestly "not evidenced" (baseline note), not a control failure.
_CONTROL_STAGES = frozenset({STAGE_LOGGED, STAGE_RETAINED, STAGE_REUSED, STAGE_DELETED})

# Which asset kinds evidence a flow stage by their presence.
_COLLECT_KINDS = {Asset.Kind.DATA_STORE, Asset.Kind.VECTOR_DB, Asset.Kind.API}
_TRANSMIT_KINDS = {Asset.Kind.MODEL, Asset.Kind.GATEWAY, Asset.Kind.MCP_SERVER, Asset.Kind.API}
_PROCESS_KINDS = {Asset.Kind.MODEL, Asset.Kind.AGENT, Asset.Kind.TOOL, Asset.Kind.SKILL}
_DURABLE_KINDS = {Asset.Kind.DATA_STORE, Asset.Kind.VECTOR_DB}

_WORD_RE = re.compile(r"[a-z0-9]+")
# Tokens in a retention/deletion assertion that name an actual erasure/expiry
# control (so a deletion stage is only evidenced when erasure is genuinely named,
# never assumed).
_DELETION_TOKENS = frozenset(
    {"delete", "deleted", "deletion", "erase", "erasure", "expire", "expiry", "expires", "purge", "ttl", "removal"}
)
# A "zero retention" retention window also names deletion (nothing is kept). Kept
# to explicit phrases so a numeric window like "90 days" is never misread as one.
_ZERO_RETENTION = ("zero retention", "zero-retention", "no retention", "not retained", "none retained")


def _stage_row(stage: str) -> dict:
    return {
        "stage": stage,
        "stage_label": STAGE_LABELS[stage],
        "control_stage": stage in _CONTROL_STAGES,
        "components": [],
    }


def _component(*, name: str, kind_label: str, how: str, evidence_class: str) -> dict:
    """One component that evidences a stage, with how it does and how strongly."""
    return {
        "name": name,
        "kind_label": kind_label,
        "how": how,
        "evidence_class": evidence_class,
        "evidence_class_label": EvidenceClass(evidence_class).label,
    }


def _assertion_map(provider) -> dict:
    """{field: assertion} for a provider, read from whatever is prefetched."""
    return {a.field: a for a in provider.assertions.all()}


def assess_data_lifecycle(deployment) -> dict:
    """The full data-lifecycle review for a deployment: each stage, the components
    that evidence it and at what strength, and the gaps where a stage has no
    evidenced control.

    Prefetch ``assets__provider__assertions`` on the caller side. Pure and
    side-effect-free — a computed view of the stored graph, never a stored
    record."""
    assets = in_graph(deployment.assets.all())
    rows = {stage: _stage_row(stage) for stage in STAGE_ORDER}

    # --- Flow stages: evidenced by the components that carry data through them.
    # These are configuration-verified — read from the recorded asset graph.
    cfg = EvidenceClass.CONFIGURATION_VERIFIED.value
    for asset in assets:
        label = asset.get_kind_display()
        if asset.kind in _COLLECT_KINDS:
            rows[STAGE_COLLECTED]["components"].append(
                _component(name=asset.name, kind_label=label, how="holds or receives data", evidence_class=cfg)
            )
        if asset.kind in _TRANSMIT_KINDS:
            rows[STAGE_TRANSMITTED]["components"].append(
                _component(name=asset.name, kind_label=label, how="data crosses the network to it", evidence_class=cfg)
            )
        if asset.kind in _PROCESS_KINDS:
            rows[STAGE_PROCESSED]["components"].append(
                _component(name=asset.name, kind_label=label, how="acts on data", evidence_class=cfg)
            )
        if asset.kind in _DURABLE_KINDS:
            # A durable store evidences retention-at-rest, but only that the data is
            # kept — NOT that it is retained *correctly* or ever deleted.
            rows[STAGE_RETAINED]["components"].append(
                _component(
                    name=asset.name,
                    kind_label=label,
                    how="persists data at rest (retention window not evidenced by the store alone)",
                    evidence_class=cfg,
                )
            )

    # --- Logging sink evidence: an observability provider, or a component whose
    # metadata flags it as a log sink.
    for asset in assets:
        provider = getattr(asset, "provider", None)
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        logs_flag = bool(metadata.get("logs") or metadata.get("logging")) or (
            str(metadata.get("role") or "").strip().lower() in {"logs", "logging", "observability"}
        )
        if provider is not None and provider.kind == Provider.Kind.OBSERVABILITY:
            rows[STAGE_LOGGED]["components"].append(
                _component(
                    name=asset.name,
                    kind_label=asset.get_kind_display(),
                    how=f"routes to observability provider '{provider.name}'",
                    evidence_class=cfg,
                )
            )
        elif logs_flag:
            rows[STAGE_LOGGED]["components"].append(
                _component(
                    name=asset.name,
                    kind_label=asset.get_kind_display(),
                    how="declared as a log sink in its recorded configuration",
                    evidence_class=cfg,
                )
            )

    # --- Provider assertions evidence logged / retained / reused / deleted, each
    # carried at the assertion's TRUE evidence class (never upgraded).
    seen_providers: set[int] = set()
    for asset in assets:
        provider = getattr(asset, "provider", None)
        if provider is None or provider.pk in seen_providers:
            continue
        seen_providers.add(provider.pk)
        amap = _assertion_map(provider)

        logging_a = amap.get(ProviderAssertion.Field.LOGGING)
        if logging_a is not None:
            rows[STAGE_LOGGED]["components"].append(
                _component(
                    name=provider.name,
                    kind_label=f"{provider.get_kind_display()} (provider)",
                    how="declares a logging posture",
                    evidence_class=logging_a.evidence_class,
                )
            )

        retention_a = amap.get(ProviderAssertion.Field.DATA_RETENTION)
        if retention_a is not None:
            rows[STAGE_RETAINED]["components"].append(
                _component(
                    name=provider.name,
                    kind_label=f"{provider.get_kind_display()} (provider)",
                    how="declares a data-retention posture",
                    evidence_class=retention_a.evidence_class,
                )
            )
            # A retention assertion evidences DELETION only when it actually names
            # erasure/expiry (or zero retention). Otherwise deletion stays a gap —
            # "data is retained" is never read as "data is deleted".
            value = (retention_a.value or "").lower()
            # Require an AFFIRMATIVE erasure/expiry declaration — a value that names
            # a deletion word only to negate it ("no deletion offered", "deletion
            # not supported", "retained forever") must leave DELETED a gap. The
            # explicit zero-retention phrases are themselves affirmative ("nothing
            # is kept"). Conservative under-crediting is the safe/honest direction.
            names_deletion = (
                bool(set(_WORD_RE.findall(value)) & _DELETION_TOKENS) and not _negated(value)
            ) or any(z in value for z in _ZERO_RETENTION)
            if names_deletion:
                rows[STAGE_DELETED]["components"].append(
                    _component(
                        name=provider.name,
                        kind_label=f"{provider.get_kind_display()} (provider)",
                        how="retention posture names an erasure / expiry control",
                        evidence_class=retention_a.evidence_class,
                    )
                )

        trains_a = amap.get(ProviderAssertion.Field.TRAINS_ON_DATA)
        subproc_a = amap.get(ProviderAssertion.Field.SUBPROCESSORS)
        for a, how in ((trains_a, "declares a training-on-data posture"),
                       (subproc_a, "declares a subprocessor / third-party-sharing posture")):
            if a is not None:
                rows[STAGE_REUSED]["components"].append(
                    _component(
                        name=provider.name,
                        kind_label=f"{provider.get_kind_display()} (provider)",
                        how=how,
                        evidence_class=a.evidence_class,
                    )
                )

    # --- Assemble each stage: evidenced?, weakest evidence, gap + risk. ---
    stages: list[dict] = []
    for stage in STAGE_ORDER:
        row = rows[stage]
        # Deterministic component order.
        row["components"].sort(key=lambda c: (evidence_strength(c["evidence_class"]), c["name"], c["how"]))
        evidenced = bool(row["components"])
        # The weakest evidence behind the stage (a chain is as strong as its
        # weakest link) — the honest confidence floor for the stage.
        weakest = (
            max((c["evidence_class"] for c in row["components"]), key=evidence_strength)
            if evidenced
            else None
        )
        control_stage = row["control_stage"]

        gap = False
        gap_detail = None
        risk = RISK_BASELINE
        if control_stage and not evidenced:
            gap = True
            gap_detail = f"No evidenced control for the '{STAGE_LABELS[stage]}' stage."
            risk = RISK_ELEVATED if stage != STAGE_DELETED else RISK_HIGH
        elif control_stage and evidenced:
            # A control evidenced only weakly (vendor-asserted or softer) is a weak
            # control — still a gap, at a lower risk than a total absence.
            if evidence_strength(weakest) >= evidence_strength(EvidenceClass.VENDOR_ASSERTED):
                gap = True
                gap_detail = (
                    f"The '{STAGE_LABELS[stage]}' control is evidenced only weakly "
                    f"({EvidenceClass(weakest).label}) — not independently verified."
                )
                risk = RISK_ELEVATED
        elif not control_stage and not evidenced:
            # A flow stage the graph does not populate: honestly not evidenced,
            # never "compliant". Baseline — it is a coverage note, not a control gap.
            gap_detail = f"The '{STAGE_LABELS[stage]}' stage is not evidenced in the asset graph."

        stages.append(
            {
                "stage": stage,
                "stage_label": STAGE_LABELS[stage],
                "control_stage": control_stage,
                "evidenced": evidenced,
                "components": row["components"],
                "weakest_evidence": weakest,
                "weakest_evidence_label": EvidenceClass(weakest).label if weakest else None,
                "gap": gap,
                "gap_detail": gap_detail,
                "risk": risk,
            }
        )

    gap_rollup = sorted(
        (
            {"stage": s["stage"], "stage_label": s["stage_label"], "risk": s["risk"], "detail": s["gap_detail"]}
            for s in stages
            if s["gap"]
        ),
        key=lambda g: (_RISK_ORDER.index(g["risk"]), STAGE_ORDER.index(g["stage"])),
    )

    worst_risk = None
    for s in stages:
        if s["gap"]:
            worst_risk = s["risk"] if worst_risk is None else _max_risk(worst_risk, s["risk"])

    summary = {
        "stages_total": len(STAGE_ORDER),
        "evidenced": sum(1 for s in stages if s["evidenced"]),
        "not_evidenced": sum(1 for s in stages if not s["evidenced"]),
        "control_gaps": sum(1 for s in stages if s["gap"]),
        "worst_risk": worst_risk,
    }

    return {
        "stages": stages,
        "gaps": gap_rollup,
        "summary": summary,
    }
