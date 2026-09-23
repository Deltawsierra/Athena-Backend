"""Operational-risk register — four narrow operational-risk classes, honestly read (Phase 3.9).

The operational-risk facing layer of the assurance spine, kept deliberately
**narrow**. The roadmap scopes an operational view to "only where it affects
security, safety, evidence, cost risk, or deployment trust. Do not become
Datadog." So this module does **not** report latency, throughput, uptime
percentages, or any generic metric. It reports exactly four operational-risk
classes, each tied to a security/safety/cost/deployment-trust concern:

1. **unbounded-loop / retry-storm** — an agent looping or retrying without bound
   (a *safety* concern: unbounded autonomous action).
2. **denial-of-wallet / cost-runaway** — spend that can be driven up without limit
   (a *cost* concern).
3. **token-storm** — unbounded token consumption (a *cost* concern).
4. **provider-outage / no-fallback** — a single provider with no failover
   (a *deployment-trust* / continuity concern).

**This is a REUSE-ONLY computed assessment.** Like its siblings
(:mod:`assurance.operational`, :mod:`assurance.capability`,
:mod:`assurance.business_impact`) it is computed on read: a pure function of the
stored assurance graph, deterministic, None-safe, with no new model, no
migration, no stored record, and no timestamp in the returned content.

**The honesty discipline is the whole point.** These are largely *runtime*
signals that live in the engine's execution layer, not necessarily in this
backend graph. This module is therefore an honest **register**, not a green
dashboard:

- Where a **real signal exists in the stored graph**, a class derives an honest
  ordinal risk band from it and cites the signal:
    * *provider-outage* is read structurally from the deployment's model-provider
      dependencies (assets → :class:`~assurance.models.Provider`): a single
      evidenced model provider is a single point of failure with no evidenced
      failover; two or more mean an alternative path exists in the graph (though
      *configured* failover remains a runtime signal).
    * *retry-storm* is read structurally from the deployment's autonomous
      ``agent`` assets — the same signal :mod:`assurance.capability` reads as
      "runs an agentic loop that can chain steps without per-step human
      approval." The loop *surface* is in the graph; the *bound* on it (a max-
      iteration / retry cap) is a runtime signal that is not.
    * every class also escalates on a **direct finding** the engine ingested whose
      ``finding_type`` names the class (e.g. OWASP LLM10 ``unbounded_consumption``,
      which spans denial-of-wallet and token exhaustion), banded by the worst
      active severity landing on it.
- Where the graph has **no basis**, the class is marked ``status="unmapped"`` /
  ``observed=False`` with ``risk=None`` — a runtime signal the engine will feed
  later. It is **correct and expected** that denial-of-wallet and token-storm read
  ``unmapped`` on a graph that records no budget, rate-limit, spend, or token-cap:
  those controls live in the engine, not here. An unmapped class is **never**
  rendered as a fabricated ``0`` / ``0%``, and **never** as "no risk", "safe", or
  "secure". Absence of data is *unmapped/unknown*, never *clear*.

The overall roll-up is **weakest-honest**: it reflects the worst *observed* risk,
and it surfaces the unmapped classes as open gaps rather than counting them as a
clean pass. A deployment with nothing observed rolls up to ``unmapped``, never to
a green band.

Prefetch ``assets__provider`` and ``findings`` on the caller side to keep it
query-light. Pure and side-effect-free; deterministic.
"""

from __future__ import annotations

from .models import (
    RESOLVED_FINDING_STATUSES,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Asset,
    Provider,
    severity_rank,
)
from .governance import GOVERNED

# ---------------------------------------------------------------------------
# Ordinal risk bands
# ---------------------------------------------------------------------------

# Ordinal operational-risk bands, most concerning first. A band is emitted ONLY
# for a class with a real basis in the stored graph; a class with no basis carries
# ``risk=None`` and ``status="unmapped"`` instead. There is deliberately no
# "low"/"baseline"/"clear" band: an *observed* operational risk floors at
# ``moderate`` so nothing this register surfaces ever reads as an unearned clean
# pass, and an *unmapped* class reads honestly as a gap rather than as a low score.
RISK_HIGH = "high"
RISK_ELEVATED = "elevated"
RISK_MODERATE = "moderate"
_RISK_ORDER = (RISK_HIGH, RISK_ELEVATED, RISK_MODERATE)  # index 0 = most concerning

# A class with no basis in the stored graph. Its risk is None, never a fabricated
# 0 — the honest read is "we have no signal", not "we have a clean signal".
STATUS_OBSERVED = "observed"
STATUS_UNMAPPED = "unmapped"


def _worse(a: str | None, b: str | None) -> str | None:
    """The more concerning of two ordinal bands, either possibly None (no basis).
    None means "no observed risk read", never "no risk"."""
    if a is None:
        return b
    if b is None:
        return a
    return a if _RISK_ORDER.index(a) <= _RISK_ORDER.index(b) else b


def _band_from_severity(rank: int) -> str:
    """The ordinal risk band an active finding of a given severity contributes.
    Floored at ``moderate``: an ingested finding naming a real operational risk is
    never read below moderate, so a low/info-severity signal is still surfaced as a
    live concern rather than rounded down to a clean pass."""
    if rank >= severity_rank(SEVERITY_HIGH):
        return RISK_HIGH
    if rank >= severity_rank(SEVERITY_MEDIUM):
        return RISK_ELEVATED
    return RISK_MODERATE


# ---------------------------------------------------------------------------
# What "active" means (mirrors the rest of the assurance layer)
# ---------------------------------------------------------------------------

# Findings in these states are resolved — no longer live operational risk. Mirrors
# ``assurance.decision``/``assurance.compliance``/``assurance.business_impact`` so
# every view agrees on what "active" means.
# The one definition lives in ``assurance.models`` beside the statuses themselves.
# Seven modules each kept their own copy of this set, and every one of their
# comments said it "mirrors" the others so every view would agree on what "active"
# means -- which is precisely the arrangement that lets them stop agreeing. Adding
# a status meant editing eight places and silently disagreeing if you missed one.
_RESOLVED_STATUSES = RESOLVED_FINDING_STATUSES

# The classifications that make an asset *managed* — a governed component. Anything
# else (unmanaged / unknown / high_risk / retired) is a shadow source. Mirrors
# ``assurance.capability._MANAGED``.
# The single definition, not a fourth private copy of it.
_MANAGED = GOVERNED


# ---------------------------------------------------------------------------
# The four operational-risk classes (curated module data)
# ---------------------------------------------------------------------------

# Concerns the roadmap allows an operational view to touch. Each class ties to
# exactly one, so the register never drifts into generic metrics.
CONCERN_SAFETY = "safety"
CONCERN_COST = "cost"
CONCERN_DEPLOYMENT_TRUST = "deployment_trust"
_CONCERN_LABELS = {
    CONCERN_SAFETY: "Safety of autonomous action",
    CONCERN_COST: "Cost risk",
    CONCERN_DEPLOYMENT_TRUST: "Deployment trust / continuity",
}

CLASS_RETRY_STORM = "retry_storm"
CLASS_DENIAL_OF_WALLET = "denial_of_wallet"
CLASS_TOKEN_STORM = "token_storm"
CLASS_PROVIDER_OUTAGE = "provider_outage"

# Per-class metadata: label, the concern it ties to, the question it asks, and the
# substring matchers (case-insensitive, on ``finding_type``) for a direct finding
# the engine ingested that names this class. The matchers are aligned to the real
# engine vocabulary this repo already carries — notably OWASP LLM10
# ``unbounded_consumption`` (denial-of-wallet + token exhaustion, NIST SC-5
# Denial-of-Service Protection) — plus the plain-language terms an engine finding
# would use. A finding whose type matches nothing here simply does not signal this
# class; it is not forced onto a class it does not belong to.
_CLASS_SPECS: dict[str, dict] = {
    CLASS_RETRY_STORM: {
        "label": "Unbounded loop / retry storm",
        "concern": CONCERN_SAFETY,
        "question": "Can an agent loop or retry without an evidenced bound?",
        "finding_keywords": (
            "unbounded_loop",
            "infinite_loop",
            "loop",
            "retry",
            "runaway",
            "recursion",
            "recursive",
            "storm",
        ),
        # What a runtime signal would have to say to resolve this honestly.
        "runtime_signal": (
            "A per-agent iteration / retry bound (max steps, max retries, a "
            "backoff and a circuit-breaker) is an engine execution-layer signal; "
            "this backend graph does not record it, so the presence of a bound "
            "cannot be confirmed here."
        ),
    },
    CLASS_DENIAL_OF_WALLET: {
        "label": "Denial-of-wallet / cost runaway",
        "concern": CONCERN_COST,
        "question": "Can spend be driven up without an evidenced limit?",
        "finding_keywords": (
            "denial_of_wallet",
            "wallet",
            "cost_runaway",
            "cost",
            "billing",
            "spend",
            "budget",
            "unbounded_consumption",
        ),
        "runtime_signal": (
            "A spend budget / rate limit / quota is an engine execution-layer "
            "control; this backend graph records no budget, spend, or rate-limit "
            "signal, so whether spend is bounded cannot be read here."
        ),
    },
    CLASS_TOKEN_STORM: {
        "label": "Token storm / unbounded token consumption",
        "concern": CONCERN_COST,
        "question": "Can token consumption grow without an evidenced cap?",
        "finding_keywords": (
            "token",
            "unbounded_consumption",
            "context_window",
            "prompt_bomb",
        ),
        "runtime_signal": (
            "A max-tokens / context-window / per-request token cap is an engine "
            "execution-layer control; this backend graph records no token-limit "
            "signal, so whether token use is bounded cannot be read here."
        ),
    },
    CLASS_PROVIDER_OUTAGE: {
        "label": "Provider outage / no fallback",
        "concern": CONCERN_DEPLOYMENT_TRUST,
        "question": "Does a single provider carry the deployment with no failover?",
        "finding_keywords": (
            "provider_outage",
            "service_outage",
            "outage",
            "no_fallback",
            "fallback",
            "failover",
            "single_point_of_failure",
            "availability",
            "provider_down",
        ),
        "runtime_signal": (
            "Whether failover between providers is actually configured and "
            "exercised is an engine execution-layer signal; this backend graph "
            "evidences the provider dependencies but not a live failover path."
        ),
    },
}
# Stable reporting order for a deterministic tie-break.
_CLASS_ORDER = {
    CLASS_RETRY_STORM: 0,
    CLASS_DENIAL_OF_WALLET: 1,
    CLASS_TOKEN_STORM: 2,
    CLASS_PROVIDER_OUTAGE: 3,
}


# ---------------------------------------------------------------------------
# Signal helpers (pure reads of the stored graph)
# ---------------------------------------------------------------------------


def _finding_signal(active_findings, keywords) -> tuple[str | None, int, list[dict]]:
    """The direct-finding signal for a class: the ordinal band from the worst
    *active* finding whose ``finding_type`` matches one of the class keywords, the
    count of such findings, and the cited signals. Case- and whitespace-insensitive
    substring match on the type, mirroring how :mod:`assurance.capability` matches a
    declared permission. Returns ``(None, 0, [])`` when nothing matches — no basis,
    never a fabricated clean read."""
    band: str | None = None
    count = 0
    signals: list[dict] = []
    for finding in active_findings:
        ftype = (finding.finding_type or "").strip().lower()
        if not ftype:
            continue
        if not any(kw in ftype for kw in keywords):
            continue
        count += 1
        band = _worse(band, _band_from_severity(severity_rank(finding.severity)))
        signals.append(
            {
                "source": "finding",
                "reference": str(finding.uuid),
                "finding_type": finding.finding_type,
                "title": finding.title,
                "severity": finding.severity,
                "detail": f"active {finding.severity} finding '{finding.title}' names this class",
            }
        )
    # Deterministic: worst severity first, then finding_type, then title.
    signals.sort(key=lambda s: (-severity_rank(s["severity"]), s["finding_type"], s["title"]))
    return band, count, signals


def _asset_signal(asset: Asset, detail: str) -> dict:
    """One cited structural signal: the component that evidences a class."""
    return {
        "source": "asset",
        "reference": str(asset.uuid),
        "asset_name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        "managed": asset.classification in _MANAGED,
        "detail": detail,
    }


def _provider_signal(provider: Provider, detail: str) -> dict:
    """One cited structural signal: a provider the deployment depends on."""
    return {
        "source": "provider",
        "reference": str(provider.uuid),
        "provider_name": provider.name,
        "kind": provider.kind,
        "kind_label": provider.get_kind_display(),
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Per-class assessments
# ---------------------------------------------------------------------------


def _class_result(
    key: str,
    *,
    structural_band: str | None,
    structural_signals: list[dict],
    structural_notes: list[str],
    active_findings,
) -> dict:
    """Assemble one class's honest read from its structural signal (if any) and its
    direct-finding signal. A class is ``observed`` when *either* basis fired;
    otherwise it is honestly ``unmapped`` with ``risk=None`` — never a fabricated
    band, count-as-clean, or 0."""
    spec = _CLASS_SPECS[key]
    finding_band, finding_count, finding_signals = _finding_signal(
        active_findings, spec["finding_keywords"]
    )

    basis: list[str] = []
    if structural_band is not None:
        basis.append("structural")
    if finding_band is not None:
        basis.append("finding")

    risk = _worse(structural_band, finding_band)
    observed = risk is not None

    signals = list(structural_signals) + finding_signals

    return {
        "key": key,
        "label": spec["label"],
        "concern": spec["concern"],
        "concern_label": _CONCERN_LABELS[spec["concern"]],
        "question": spec["question"],
        "status": STATUS_OBSERVED if observed else STATUS_UNMAPPED,
        "observed": observed,
        # Ordinal band ONLY with a real basis; None (not 0) when unmapped.
        "risk": risk,
        "basis": basis,
        "active_finding_count": finding_count,
        "signals": signals,
        # Always present: the runtime control that would let this be read fully, and
        # the honest statement that it is not in this graph. This is what keeps an
        # unmapped class reading as a gap rather than as a clean pass.
        "runtime_signal": spec["runtime_signal"],
        "notes": structural_notes,
    }


def _assess_provider_outage(assets, active_findings) -> dict:
    """provider-outage / no-fallback, read structurally from the model-provider
    dependency graph. The one class with a strong stored-graph basis.

    A single evidenced model provider is an honest ``high`` — a single point of
    failure with no alternative provider anywhere in the graph. Two or more mean an
    alternative path exists in the graph, so the *no-fallback* concern softens to
    ``moderate`` — but never to a clean pass, because whether failover is actually
    *configured* is a runtime signal this graph does not carry. Zero evidenced model
    providers is no basis at all: the class falls to the direct-finding signal, and
    to ``unmapped`` if there is none. Absence of a provider dependency is *unmapped*,
    never *safe*."""
    model_providers: dict[str, Provider] = {}
    gateway_present = False
    for asset in assets:
        if asset.kind == Asset.Kind.GATEWAY:
            gateway_present = True
        provider = asset.provider
        if provider is None:
            continue
        if provider.kind == Provider.Kind.GATEWAY:
            gateway_present = True
        if provider.kind == Provider.Kind.MODEL_PROVIDER:
            model_providers[str(provider.uuid)] = provider

    n = len(model_providers)
    structural_band: str | None = None
    structural_signals: list[dict] = []
    structural_notes: list[str] = []

    if n == 1:
        provider = next(iter(model_providers.values()))
        structural_band = RISK_HIGH
        structural_signals.append(
            _provider_signal(
                provider,
                "the only model provider evidenced for this deployment — a single "
                "point of failure with no alternative provider in the graph",
            )
        )
        if gateway_present:
            structural_notes.append(
                "An AI gateway is present, but only one model provider is evidenced "
                "behind it, so the graph shows no alternative provider to fail over to."
            )
    elif n >= 2:
        structural_band = RISK_MODERATE
        for provider in sorted(model_providers.values(), key=lambda p: p.name):
            structural_signals.append(
                _provider_signal(
                    provider,
                    "one of multiple model providers the deployment depends on — an "
                    "alternative path exists in the graph",
                )
            )
        structural_notes.append(
            f"{n} distinct model providers are evidenced, so an alternative provider "
            "exists in the graph; whether failover between them is configured and "
            "exercised is a runtime signal not recorded here."
        )
    else:
        # No model provider dependency in the graph — no structural basis. Note the
        # gap honestly rather than reading it as no risk.
        structural_notes.append(
            "No model-provider dependency is evidenced in the asset graph, so "
            "provider redundancy cannot be read structurally."
        )

    return _class_result(
        CLASS_PROVIDER_OUTAGE,
        structural_band=structural_band,
        structural_signals=structural_signals,
        structural_notes=structural_notes,
        active_findings=active_findings,
    )


def _assess_retry_storm(assets, active_findings) -> dict:
    """unbounded-loop / retry-storm, read structurally from the deployment's
    autonomous ``agent`` assets.

    An ``agent`` asset's declared power (see :mod:`assurance.capability`) is exactly
    "runs an agentic loop that can chain steps and invoke tools without per-step
    human approval" — so the *loop surface* is a real, stored-graph signal that this
    class's exposure exists. What the graph does **not** record is the *bound* on
    that loop (a max-iteration / retry cap): that is a runtime signal. So the honest
    structural read is ``elevated`` (an autonomous-loop surface is present and no
    bound is evidenced), raised to ``high`` when the agent is a shadow (unmanaged)
    component — mirroring the capability map's shadow-raises-one-band discipline. No
    agent asset and no direct finding is *unmapped*, never *bounded* or *safe*."""
    agents = [a for a in assets if a.kind == Asset.Kind.AGENT]
    structural_band: str | None = None
    structural_signals: list[dict] = []
    structural_notes: list[str] = []

    if agents:
        any_shadow = any(a.classification not in _MANAGED for a in agents)
        structural_band = RISK_HIGH if any_shadow else RISK_ELEVATED
        for agent in sorted(agents, key=lambda a: a.name):
            managed = agent.classification in _MANAGED
            structural_signals.append(
                _asset_signal(
                    agent,
                    "an autonomous agent that runs an agentic loop; the graph "
                    "records no bound on its iterations or retries"
                    + ("" if managed else " (shadow / unmanaged component)"),
                )
            )
        structural_notes.append(
            "The autonomous-loop surface is evidenced by the agent asset(s); the "
            "bound on the loop (max iterations / retry cap) is a runtime signal not "
            "recorded here, so an unbounded loop cannot be ruled out."
        )
    else:
        structural_notes.append(
            "No autonomous agent asset is evidenced, so an agentic-loop surface "
            "cannot be read structurally."
        )

    return _class_result(
        CLASS_RETRY_STORM,
        structural_band=structural_band,
        structural_signals=structural_signals,
        structural_notes=structural_notes,
        active_findings=active_findings,
    )


def _assess_cost_class(key: str, assets, active_findings) -> dict:
    """denial-of-wallet / cost-runaway and token-storm. These have **no structural
    control signal** in the stored graph: nothing here records a budget, a rate
    limit, a spend figure, or a token cap — those are engine execution-layer
    controls. So the honest default is ``unmapped``, and the class becomes
    ``observed`` only when the engine has ingested a direct finding that names it
    (e.g. OWASP LLM10 ``unbounded_consumption``).

    The cost-*exposure* surface — that a metered model provider is reachable — is
    recorded as an honest note for context, but it is deliberately **not** a risk
    band: every AI deployment calls a paid model, so its mere presence is baseline,
    not a risk. The risk is *unbounded* spend/tokens, which requires knowing there is
    no cap — the signal the graph lacks. It is therefore correct and expected that
    this class reads ``unmapped`` here."""
    metered = [
        a
        for a in assets
        if a.kind == Asset.Kind.MODEL
        or (a.provider is not None and a.provider.kind == Provider.Kind.MODEL_PROVIDER)
    ]
    structural_notes: list[str] = []
    if metered:
        noun = "spend" if key == CLASS_DENIAL_OF_WALLET else "token consumption"
        structural_notes.append(
            f"{len(metered)} metered model component(s) are in the graph, so a "
            f"cost-exposure surface exists; no limit on {noun} is recorded, so "
            "whether it is bounded is a runtime signal, not readable here."
        )
    else:
        structural_notes.append(
            "No metered model component is evidenced, so even the cost-exposure "
            "surface cannot be read structurally."
        )
    # No structural band by design — the *control* is a runtime signal.
    return _class_result(
        key,
        structural_band=None,
        structural_signals=[],
        structural_notes=structural_notes,
        active_findings=active_findings,
    )


# ---------------------------------------------------------------------------
# The register
# ---------------------------------------------------------------------------


def assess_operational_risk(deployment) -> dict:
    """The narrow operational-risk register for a deployment: an honest read of the
    four operational-risk classes (unbounded-loop/retry-storm, denial-of-wallet,
    token-storm, provider-outage/no-fallback), each tied to a security/safety/cost/
    deployment-trust concern.

    A REUSE-ONLY computed assessment: a pure function of the stored graph — no new
    record, no migration, no timestamp. Prefetch ``assets__provider`` and
    ``findings`` on the caller side.

    Every class either derives an ordinal ``risk`` band from a **real signal** in
    the graph (a structural provider/agent signal and/or a direct finding, each
    cited) or is honestly ``unmapped`` (``risk=None``, ``observed=False``) as a
    runtime signal the engine will feed later. Nothing here fabricates a ``0`` /
    ``0%`` for an unmapped class, and nothing reads "no risk", "safe", or "secure"
    as an unearned fact — absence of data is *unmapped*, never *clear*. The overall
    roll-up is weakest-honest: it reflects the worst *observed* risk and surfaces
    the unmapped classes as open gaps rather than as a clean pass."""
    assets = list(deployment.assets.all())
    active_findings = [
        f for f in deployment.findings.all() if f.status not in _RESOLVED_STATUSES
    ]

    classes = [
        _assess_retry_storm(assets, active_findings),
        _assess_cost_class(CLASS_DENIAL_OF_WALLET, assets, active_findings),
        _assess_cost_class(CLASS_TOKEN_STORM, assets, active_findings),
        _assess_provider_outage(assets, active_findings),
    ]
    # Most concerning first: observed before unmapped, then by risk band, then the
    # stable curated order. Deterministic.
    classes.sort(
        key=lambda c: (
            0 if c["observed"] else 1,
            _RISK_ORDER.index(c["risk"]) if c["risk"] is not None else len(_RISK_ORDER),
            _CLASS_ORDER[c["key"]],
        )
    )

    observed = [c for c in classes if c["observed"]]
    unmapped_keys = [c["key"] for c in classes if not c["observed"]]
    worst_risk: str | None = None
    for c in observed:
        worst_risk = _worse(worst_risk, c["risk"])

    summary = {
        "total_classes": len(classes),
        "observed_classes": len(observed),
        "unmapped_classes": len(unmapped_keys),
        "high": sum(1 for c in classes if c["risk"] == RISK_HIGH),
        "elevated": sum(1 for c in classes if c["risk"] == RISK_ELEVATED),
        "moderate": sum(1 for c in classes if c["risk"] == RISK_MODERATE),
        # Worst OBSERVED band; None (not 0) when nothing is observed.
        "worst_risk": worst_risk,
        # The classes with no basis, surfaced as gaps — never counted as a pass.
        "unmapped": unmapped_keys,
    }

    # Weakest-honest overall: the worst observed risk, with the unmapped classes
    # surfaced as remaining gaps. When nothing is observed the overall is honestly
    # ``unmapped`` — never a clean band, a 0, or a "no risk".
    overall = {
        "status": STATUS_OBSERVED if observed else STATUS_UNMAPPED,
        "risk": worst_risk,
        "unmapped_classes": len(unmapped_keys),
        "note": _overall_note(worst_risk, len(observed), len(unmapped_keys)),
    }

    return {
        "system": {
            "name": deployment.name,
            "uuid": str(deployment.uuid),
            "environment": deployment.environment,
            "environment_label": deployment.get_environment_display(),
        },
        "classes": classes,
        "summary": summary,
        "overall": overall,
    }


def _overall_note(worst_risk: str | None, observed: int, unmapped: int) -> str:
    """A deterministic one-line roll-up worded to stay honest: it states the worst
    observed band (or that nothing is observed) and always names the unmapped
    classes as open gaps, so the roll-up is never read as a clean pass."""
    if observed:
        head = f"Worst observed operational risk is '{worst_risk}'."
    else:
        head = (
            "No operational-risk class has a basis in the stored graph; all four are "
            "runtime signals the engine feeds."
        )
    if unmapped:
        tail = (
            f" {unmapped} of 4 class(es) are unmapped runtime signals and remain "
            "open gaps."
        )
    else:
        tail = " All four classes have a basis in the stored graph."
    return head + tail
