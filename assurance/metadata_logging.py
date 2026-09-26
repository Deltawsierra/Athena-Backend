"""Metadata & Logging Risk — where prompts, traces, embeddings and metadata get
logged, and what sensitive detail could leak there (Phase 3.5, data & context).

The last of the four "data & context" assessments. Logs are the quiet exfil path:
prompts, retrieved context, tool arguments and identifiers land in an
observability sink that is often outside the approved boundary and rarely
redacted. This assessment answers *where does this system log, what sensitive
category could reach those logs, and is there an evidenced control?* — from
signals that already exist, inventing no sink:

- **Logging sinks** are the graph's log destinations: a component whose provider
  is an observability/logging vendor (the one signal :mod:`assurance.route` uses
  for its logs layer), a component its recorded ``metadata`` flags as a log sink,
  and a provider that carries a ``logging`` assertion. Each is carried at the
  evidence strength of the signal behind it.
- **Sensitive categories** that *could* reach a sink are grounded in what the
  deployment actually handles: **prompts/traces** when a model or gateway is
  present, **embeddings** when a vector store is present, **PII** when a
  data-bearing component evidences personal data (reusing
  :func:`assurance.personal_context` — never re-deriving it), and **table/column
  lineage** when a data store is present. A category is reported only when the
  graph evidences the data it describes.
- **Gaps** are sinks that receive sensitive categories with **no evidenced
  control**: a provider logging assertion that does not name redaction/scrubbing,
  or a shadow/unmanaged sink. An evidenced control is read honestly at its class —
  a ``vendor_asserted`` redaction claim is a weak control, not a verified one.

It is honest in the same way its siblings are:

- Only logging the graph evidences is flagged; a deployment with no sink reads as
  having none evidenced, never "no logging risk" / "safe".
- **No sensitive value is ever emitted** — the assessment reports the *presence*
  of a category and its lineage (which sink, from what), never a logged datum, a
  prompt, or a secret.
- An unknown reads unknown; an unevidenced control is a gap, never a pass.

Computed on read (a pure function of the stored graph), like
:func:`assurance.route.build_route_map` — no new record, no migration, no
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
    _MANAGED,
    _RISK_ORDER,
    _RISK_RAISED,
    _max_risk,
)
from .models import Asset, EvidenceClass, Provider, ProviderAssertion, evidence_strength
from .personal_context import DATA_BEARING_KINDS, _sensitivity

# Sensitive categories that could reach a log sink. Each is reported only when the
# deployment evidences the data it describes.
CATEGORY_PROMPTS = "prompts"
CATEGORY_EMBEDDINGS = "embeddings"
CATEGORY_PII = "pii"
CATEGORY_LINEAGE = "lineage"
CATEGORY_SECRETS = "secrets"

_CATEGORY_LABELS = {
    CATEGORY_PROMPTS: "Prompts / traces",
    CATEGORY_EMBEDDINGS: "Embeddings",
    CATEGORY_PII: "Personal data (PII)",
    CATEGORY_LINEAGE: "Table / column lineage",
    CATEGORY_SECRETS: "Secrets / credentials",
}
# A stable, most-concerning-first category order for deterministic tie-breaks.
_CATEGORY_ORDER = {
    key: i for i, key in enumerate((CATEGORY_SECRETS, CATEGORY_PII, CATEGORY_PROMPTS, CATEGORY_EMBEDDINGS, CATEGORY_LINEAGE))
}

_WORD_RE = re.compile(r"[a-z0-9]+")
# Affirmative tokens in a logging assertion that name an actual leak-limiting
# control (so a control is only credited when redaction/scrubbing is genuinely
# named). Negation words are deliberately NOT here: a value like "no redaction"
# names a control word only to say it is absent, and must never read as a control
# — that negation is handled by boundary._negated in _logging_control.
_CONTROL_TOKENS = frozenset(
    {"redact", "redacted", "redaction", "scrub", "scrubbed", "mask", "masked", "masking",
     "anonymize", "anonymized", "anonymised", "filter", "filtered", "sanitize", "sanitized"}
)


def _log_sink_signal(asset) -> tuple[str, str] | None:
    """Whether a component is a log sink, and how it was determined:
    ``(basis, evidence_class)`` or ``None``. The observability-provider signal and
    the metadata flag are both configuration-verified (read from the recorded
    graph)."""
    provider = getattr(asset, "provider", None)
    if provider is not None and provider.kind == Provider.Kind.OBSERVABILITY:
        return (
            f"routes to observability provider '{provider.name}'",
            EvidenceClass.CONFIGURATION_VERIFIED.value,
        )
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    role = str(metadata.get("role") or "").strip().lower()
    if metadata.get("logs") or metadata.get("logging") or role in {"logs", "logging", "observability"}:
        return ("declared as a log sink in its recorded configuration", EvidenceClass.CONFIGURATION_VERIFIED.value)
    return None


def _handled_categories(assets: list) -> list[dict]:
    """The sensitive categories the deployment handles, each with the evidence for
    why it is in play. Grounded in what the graph attests — a category the graph
    does not evidence is not reported."""
    kinds = {a.kind for a in assets}
    handled: list[dict] = []

    if kinds & {Asset.Kind.MODEL, Asset.Kind.GATEWAY}:
        handled.append(
            {"category": CATEGORY_PROMPTS, "basis": "a model or gateway processes prompts and traces"}
        )
    if Asset.Kind.VECTOR_DB in kinds:
        handled.append(
            {"category": CATEGORY_EMBEDDINGS, "basis": "a vector store holds embeddings"}
        )
    # PII only when a data-bearing component evidences personal data (reused, never
    # re-derived, from personal_context's sensitivity reading).
    personal = sorted(
        a.name
        for a in assets
        if a.kind in DATA_BEARING_KINDS and _sensitivity(a)[0] == "personal"
    )
    if personal:
        handled.append(
            {
                "category": CATEGORY_PII,
                "basis": "personal data is evidenced in: " + ", ".join(personal),
            }
        )
    if Asset.Kind.DATA_STORE in kinds:
        handled.append(
            {"category": CATEGORY_LINEAGE, "basis": "a data store exposes table / column lineage"}
        )

    for h in handled:
        h["label"] = _CATEGORY_LABELS[h["category"]]
    handled.sort(key=lambda h: _CATEGORY_ORDER[h["category"]])
    return handled


def _sink_dict(asset, basis, evidence_class, handled, logging_control) -> dict:
    """Assemble one logging sink: what it is, how we know it logs, the sensitive
    categories that could reach it, and its gaps. Pure — reads only what was
    passed. ``logging_control`` is ``(evidenced_bool, evidence_class, detail)`` for
    the sink's provider logging assertion, or ``None`` when no such assertion."""
    managed = asset.classification in _MANAGED
    base_risk = RISK_BASELINE if managed else _RISK_RAISED[RISK_BASELINE]

    categories = [
        {"category": h["category"], "label": h["label"], "basis": h["basis"]} for h in handled
    ]

    gaps: list[dict] = []

    control_evidenced = bool(logging_control and logging_control[0])
    # A sink receiving sensitive categories with no evidenced leak-limiting control.
    sensitive_present = any(c["category"] in (CATEGORY_PII, CATEGORY_SECRETS, CATEGORY_PROMPTS) for c in categories)
    if categories and not control_evidenced:
        risk = RISK_HIGH if sensitive_present else RISK_ELEVATED
        gaps.append(
            {
                "type": "logged_without_control",
                "risk": risk,
                "detail": "Sensitive categories could reach this sink with no evidenced "
                "redaction / scrubbing control: "
                + ", ".join(c["label"] for c in categories),
            }
        )
    elif categories and logging_control and control_evidenced and logging_control[1] is not None:
        # A control is named but only weakly evidenced (vendor-asserted / unknown):
        # a weak control, still a gap, at lower risk than none.
        if evidence_strength(logging_control[1]) >= evidence_strength(EvidenceClass.VENDOR_ASSERTED):
            gaps.append(
                {
                    "type": "control_unverified",
                    "risk": RISK_ELEVATED,
                    "detail": f"A logging control is declared but only "
                    f"{EvidenceClass(logging_control[1]).label.lower()} — not independently verified.",
                }
            )

    # A shadow / unmanaged sink: an ungoverned place data lands.
    if not managed:
        gaps.append(
            {
                "type": "shadow_sink",
                "risk": RISK_HIGH,
                "detail": "The log sink is unmanaged / shadow — an ungoverned destination for logged data.",
            }
        )

    gaps.sort(key=lambda g: (_RISK_ORDER.index(g["risk"]), g["type"]))

    risk = base_risk
    for gap in gaps:
        risk = _max_risk(risk, gap["risk"])

    return {
        "asset_name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "identifier": asset.identifier,
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        "managed": managed,
        "provider_name": asset.provider.name if getattr(asset, "provider", None) else None,
        "basis": basis,
        "evidence_class": evidence_class,
        "evidence_class_label": EvidenceClass(evidence_class).label,
        "sensitive_categories": categories,
        "control_evidenced": control_evidenced,
        "control_detail": logging_control[2] if logging_control else None,
        "gaps": gaps,
        "risk": risk,
    }


def _logging_control(asset) -> tuple[bool, str | None, str | None] | None:
    """The sink provider's logging control, if it carries a ``logging`` assertion:
    ``(control_named, evidence_class, detail)``. A control is credited only when the
    assertion actually names a redaction/scrubbing (or no-logging) control — a
    vague logging value is not read as a control. ``None`` when no assertion."""
    provider = getattr(asset, "provider", None)
    if provider is None:
        return None
    assertion = next(
        (a for a in provider.assertions.all() if a.field == ProviderAssertion.Field.LOGGING),
        None,
    )
    if assertion is None:
        return None
    value = (assertion.value or "").lower()
    # Credit a redaction / scrubbing control only when an affirmative control verb
    # is named AND the value is not negated. A negated value ("no redaction",
    # "redaction disabled") names a control word only to deny it, so it must never
    # read as a control — under-crediting is the safe/honest direction.
    names_control = (
        bool(set(_WORD_RE.findall(value)) & _CONTROL_TOKENS) and not _negated(value)
    )
    detail = "logging posture names a redaction / scrubbing control" if names_control else "logging posture declared, no control named"
    return names_control, assertion.evidence_class, detail


def assess_metadata_logging(deployment) -> dict:
    """The full metadata & logging-risk assessment for a deployment: every
    evidenced logging sink, the sensitive categories that could reach it, the
    controls (or their absence), and an honest roll-up.

    Prefetch ``assets__provider__assertions`` on the caller side. Pure and
    side-effect-free — a computed view of the stored graph, never a stored
    record."""
    assets = in_graph(deployment.assets.all())
    handled = _handled_categories(assets)

    sinks: list[dict] = []
    for asset in assets:
        signal = _log_sink_signal(asset)
        if signal is None:
            continue
        basis, evidence_class = signal
        sinks.append(_sink_dict(asset, basis, evidence_class, handled, _logging_control(asset)))

    # Most-concerning first: worst risk, unmanaged before managed, then name.
    sinks.sort(key=lambda s: (_RISK_ORDER.index(s["risk"]), s["managed"], s["asset_name"]))

    gap_rollup: list[dict] = []
    for s in sinks:
        for gap in s["gaps"]:
            gap_rollup.append({**gap, "asset_name": s["asset_name"]})
    gap_rollup.sort(key=lambda g: (_RISK_ORDER.index(g["risk"]), g["type"], g["asset_name"]))

    worst_risk = None
    for s in sinks:
        worst_risk = s["risk"] if worst_risk is None else _max_risk(worst_risk, s["risk"])

    summary = {
        "sinks": len(sinks),
        "shadow_sinks": sum(1 for s in sinks if not s["managed"]),
        "sinks_without_control": sum(
            1 for s in sinks for g in s["gaps"] if g["type"] == "logged_without_control"
        ),
        "sensitive_categories_handled": len(handled),
        "gaps": len(gap_rollup),
        "worst_risk": worst_risk,
    }

    return {
        "sinks": sinks,
        "sensitive_categories_handled": handled,
        "gaps": gap_rollup,
        "summary": summary,
    }
