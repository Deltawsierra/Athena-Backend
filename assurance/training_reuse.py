"""Training / Reuse Review — is customer or internal data reused for training or
feedback, and is that VERIFIED or only ASSERTED? (Phase 3.5, data & context).

The question a procurement or data-governance reviewer must answer before a
deployment ships: *does any provider reuse this system's data — to train a model,
to share with a third party, to keep beyond the request — and how strongly do we
actually know the answer?* This assessment reconciles the signals that already
exist and refuses to launder a vendor's word into a fact:

- **Ground truth** is each provider's :class:`~assurance.models.ProviderAssertion`
  facts — ``trains_on_data`` (reuse for training/feedback), ``subprocessors``
  (third-party sharing), ``data_retention`` (reuse-by-keeping) — each carried at
  its **true** :class:`~assurance.models.EvidenceClass` and source. A
  ``vendor_asserted`` "we don't train on your data" reads as **vendor-asserted**,
  never as independently verified.
- **Posture** per fact is read with the same whole-word interpreter the boundary
  assessment uses (:func:`assurance.boundary._affirmative` /
  :func:`assurance.boundary._negated`) so "opt-in" is never read as an opt-out and
  a real reuse declaration is never lost to an incidental substring: *reused*
  (affirmatively declared), *not reused* (negated), or *unknown* (nothing
  declared).
- **Verified vs asserted** reuses :func:`assurance.vendor._is_independently_evidenced`
  — a fact is *verified* only when its evidence is stronger than a bare vendor
  claim **and** its source is not the vendor's own say-so. Nothing upgrades a
  vendor claim.

It is honest in the same way its siblings are:

- Nothing reads "safe" / "compliant". A negated-but-only-vendor-asserted reuse
  claim is **not** verified, so it is still a gap; an **unstated** reuse policy is
  a gap (reuse cannot be ruled out), never "safe".
- An **affirmatively declared** reuse is surfaced with its risk raised; a reuse
  posture known only at ``vendor_asserted`` / ``unknown`` strength is a gap.
- No data value is emitted — only the declared posture, its evidence class, and
  the components that depend on the provider.

Computed on read (a pure function of the stored graph), like
:func:`assurance.vendor.assess_vendors` — no new record, no migration, no
timestamp in the payload. Prefetch ``assets__provider__assertions`` on the caller
side. Nothing here reaches the network.
"""

from __future__ import annotations

from .boundary import _affirmative, _negated, _shares_with_third_parties
from .capability import (
    RISK_BASELINE,
    RISK_ELEVATED,
    RISK_HIGH,
    _MANAGED,
    _RISK_ORDER,
    _RISK_RAISED,
    _max_risk,
)
from .models import EvidenceClass, ProviderAssertion
from .vendor import _is_independently_evidenced

# Posture readings.
POSTURE_REUSED = "reused"
POSTURE_NOT_REUSED = "not_reused"
POSTURE_UNKNOWN = "unknown"

# The provider-assertion fields that speak to reuse, and how each is interpreted.
# ``sharing`` fields read a non-empty declaration as third-party sharing; the
# others read an affirmative training/keeping declaration as reuse.
_REUSE_FIELDS = (
    (ProviderAssertion.Field.TRAINS_ON_DATA, "training", "Reuses data to train or fine-tune a model"),
    (ProviderAssertion.Field.SUBPROCESSORS, "sharing", "Shares data with third-party subprocessors"),
    (ProviderAssertion.Field.DATA_RETENTION, "retention", "Retains data beyond the request"),
)


def _posture(field: str, kind: str, value: str) -> str:
    """The reuse posture a declared value attests for a field. A ``sharing`` field
    reuses the boundary's subprocessor reading (a named subprocessor is sharing); a
    ``training`` / ``retention`` field reuses the boundary's affirmative/negation
    reading. An empty value is honestly *unknown*, never "not reused"."""
    v = (value or "").strip()
    if not v:
        return POSTURE_UNKNOWN
    if kind == "sharing":
        return POSTURE_REUSED if _shares_with_third_parties(v) else POSTURE_NOT_REUSED
    # training / retention: an affirmative declaration is reuse; a negation is not.
    if _affirmative(v):
        return POSTURE_REUSED
    if _negated(v):
        return POSTURE_NOT_REUSED
    # A retention window like "30 days" is neither affirmative nor negated but does
    # mean data is kept (reuse-by-keeping); a training value we cannot read stays
    # unknown rather than being guessed either way.
    return POSTURE_REUSED if kind == "retention" else POSTURE_UNKNOWN


def _posture_dict(assertion, field: str, kind: str, label: str) -> dict:
    """One reuse posture from a provider assertion, carried at its true evidence
    class, with an honest ``verified`` flag that never upgrades a vendor claim."""
    posture = _posture(field, kind, assertion.value)
    verified = _is_independently_evidenced(assertion.evidence_class, assertion.source)
    return {
        "field": assertion.field,
        "field_label": assertion.get_field_display(),
        "concern": label,
        "value": assertion.value,
        "posture": posture,
        "evidence_class": assertion.evidence_class,
        "evidence_class_label": assertion.get_evidence_class_display(),
        "source": assertion.source,
        "source_label": assertion.get_source_display(),
        # Verified only when independently evidenced — a vendor claim never upgrades.
        "verified": verified,
    }


def _provider_dict(provider, assets: list) -> dict:
    """One provider's training/reuse posture: each reuse fact, whether reuse is
    possible, its gaps, and an honest risk band. Never presents a provider as
    safe."""
    amap = {a.field: a for a in provider.assertions.all()}
    postures: list[dict] = []
    for field, kind, label in _REUSE_FIELDS:
        assertion = amap.get(field)
        if assertion is not None:
            postures.append(_posture_dict(assertion, field, kind, label))
        else:
            # An unstated reuse fact: reuse cannot be ruled out. Surfaced as a gap,
            # never as "not reused" / "safe".
            postures.append(
                {
                    "field": field,
                    "field_label": ProviderAssertion.Field(field).label,
                    "concern": label,
                    "value": "",
                    "posture": POSTURE_UNKNOWN,
                    "evidence_class": EvidenceClass.NOT_DOCUMENTED.value,
                    "evidence_class_label": EvidenceClass.NOT_DOCUMENTED.label,
                    "source": "",
                    "source_label": "",
                    "verified": False,
                }
            )

    dependent = sorted(assets, key=lambda a: (a.kind, a.name))
    managed = any(a.classification in _MANAGED for a in dependent)

    # Reuse is *possible* unless every reuse fact is a verified negation. An
    # affirmative reuse, or any unknown/unverified fact, leaves reuse on the table.
    reuse_possible = not all(
        p["posture"] == POSTURE_NOT_REUSED and p["verified"] for p in postures
    )
    reuse_declared = any(p["posture"] == POSTURE_REUSED for p in postures)

    gaps: list[dict] = []
    for p in postures:
        if p["posture"] == POSTURE_REUSED:
            # Reuse is affirmatively declared. Verified reuse is a known fact to
            # govern; unverified reuse is a known fact known only on the vendor's
            # word — both are surfaced, the unverified one at higher risk.
            gaps.append(
                {
                    "type": "reuse_declared",
                    "field": p["field"],
                    "risk": RISK_ELEVATED if p["verified"] else RISK_HIGH,
                    "detail": f"{p['concern']} — declared '{p['value']}' "
                    f"({p['evidence_class_label']}"
                    + ("" if p["verified"] else ", not independently verified") + ").",
                }
            )
        elif p["posture"] == POSTURE_UNKNOWN:
            gaps.append(
                {
                    "type": "reuse_unstated",
                    "field": p["field"],
                    "risk": RISK_ELEVATED,
                    "detail": f"{p['concern']} — no policy declared; reuse cannot be ruled out.",
                }
            )
        elif p["posture"] == POSTURE_NOT_REUSED and not p["verified"]:
            gaps.append(
                {
                    "type": "reuse_denied_unverified",
                    "field": p["field"],
                    "risk": RISK_ELEVATED,
                    "detail": f"{p['concern']} — declared not reused ('{p['value']}'), but only "
                    f"{p['evidence_class_label'].lower()}; the denial is not independently verified.",
                }
            )

    gaps.sort(key=lambda g: (_RISK_ORDER.index(g["risk"]), g["field"], g["type"]))

    risk = RISK_BASELINE
    for gap in gaps:
        risk = _max_risk(risk, gap["risk"])
    if not managed and dependent:
        # An unmanaged/shadow dependency on a reusing provider is worse than a
        # governed one — raise a band, as the sibling assessments do.
        risk = _RISK_RAISED[risk]

    return {
        "provider_uuid": str(provider.uuid),
        "provider_name": provider.name,
        "kind": provider.kind,
        "kind_label": provider.get_kind_display(),
        "dependent_assets": [
            {
                "asset_name": a.name,
                "kind": a.kind,
                "kind_label": a.get_kind_display(),
                "classification": a.classification,
                "classification_label": a.get_classification_display(),
                "managed": a.classification in _MANAGED,
            }
            for a in dependent
        ],
        "postures": postures,
        "reuse_possible": reuse_possible,
        "reuse_declared": reuse_declared,
        "gaps": gaps,
        "risk": risk,
    }


def assess_training_reuse(deployment) -> dict:
    """The full training/reuse review for a deployment: each provider a component
    resolves to, its reuse posture per fact (carried at its true evidence class),
    whether reuse is possible, its gaps, and an honest roll-up.

    Prefetch ``assets__provider__assertions`` on the caller side. Pure and
    side-effect-free — a computed view of the stored graph, never a stored
    record."""
    by_provider: dict[int, dict] = {}
    for asset in deployment.assets.all():
        provider = getattr(asset, "provider", None)
        if provider is None:
            continue
        entry = by_provider.setdefault(provider.pk, {"provider": provider, "assets": []})
        entry["assets"].append(asset)

    providers = [_provider_dict(e["provider"], e["assets"]) for e in by_provider.values()]
    # Most-concerning first: worst risk, reuse-declared before not, then name.
    providers.sort(
        key=lambda p: (_RISK_ORDER.index(p["risk"]), not p["reuse_declared"], p["provider_name"])
    )

    gap_rollup: list[dict] = []
    for p in providers:
        for gap in p["gaps"]:
            gap_rollup.append({**gap, "provider_name": p["provider_name"]})
    gap_rollup.sort(key=lambda g: (_RISK_ORDER.index(g["risk"]), g["provider_name"], g["field"], g["type"]))

    worst_risk = None
    for p in providers:
        worst_risk = p["risk"] if worst_risk is None else _max_risk(worst_risk, p["risk"])

    summary = {
        "providers": len(providers),
        "reuse_declared": sum(1 for p in providers if p["reuse_declared"]),
        "reuse_possible": sum(1 for p in providers if p["reuse_possible"]),
        "verified_no_reuse": sum(
            1
            for p in providers
            if not p["reuse_possible"]  # every reuse fact a verified negation
        ),
        "gaps": len(gap_rollup),
        "worst_risk": worst_risk,
    }

    return {
        "providers": providers,
        "gaps": gap_rollup,
        "summary": summary,
    }
