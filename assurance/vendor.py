"""Third-Party Vendor Assurance — the posture of the vendors a deployment leans on.

A computed layer over signals that already exist: the deployment's
:class:`~assurance.models.Provider` rows, each provider's graded
:class:`~assurance.models.ProviderAssertion` facts (the Provider Assurance
Profile, Phase 1.5 — one assertion per field, each carrying its own
:class:`~assurance.models.EvidenceClass`), and the :class:`~assurance.models.Asset`
components that depend on each provider. It runs no scan and measures nothing; it
reconciles what discovery and the profile already recorded into a per-vendor
posture a procurement or third-party-risk reader can act on.

It is honest in the same way the rest of the assurance layer is:

- **A vendor claim reads as a vendor claim.** Each assertion is carried at its
  true evidence strength. An assertion graded ``vendor_asserted`` (or weaker), or
  one whose ``source`` is ``self_declared``, is surfaced as **vendor-asserted /
  self-attested** and counted as a gap — never promoted to "independently
  evidenced". Only an assertion backed by evidence stronger than a bare vendor
  claim *and* from a non-self-declared source counts as independently evidenced.
- **Nothing is claimed secure.** A vendor is never presented as "secure" or
  "compliant". Its roll-up is an ordinal **posture band** (the risk-band
  vocabulary :mod:`assurance.capability` already uses — ``high`` / ``elevated`` /
  ``baseline``), derived from the *weakest* evidence behind its assertions and
  raised when an unmanaged component depends on it. A weaker profile is a higher
  band; the band is a concern signal, not a grade.
- **Gaps are surfaced, not smoothed.** A vendor with no assertions at all is a
  gap (nothing declared, highest band). A dependency the deployment carries with
  **no provider behind it** (provider-less) or an **unmanaged** (shadow) component
  is surfaced as an ungoverned dependency, not silently dropped.

Computed on read (a pure function of the stored graph), like
:func:`assurance.capability.assess_capabilities` and
:func:`assurance.bom.build_ai_bom` — no new record, no migration, no timestamp in
the payload. Prefetch ``assets__provider__assertions`` on the caller side to keep
it query-light.

The return shape of :func:`assess_vendors`::

    {
      "vendors": [                         # one per provider a component resolves to
        {
          "provider_uuid": "…",
          "provider_name": "OpenAI",
          "kind": "model_provider",
          "kind_label": "Model provider",
          "region": "us-east-1",
          "assertions": [                  # its declared facts, each evidence-graded
            {
              "field": "trains_on_data",
              "field_label": "Trains on customer data",
              "value": "No — zero-retention endpoint",
              "evidence_class": "vendor_asserted",
              "evidence_class_label": "Vendor asserted",
              "source": "self_declared",
              "source_label": "Self-declared",
              "independently_evidenced": False,   # backed only by the vendor's word
              "gap": True,                        # weak/self-attested → a gap
            },
            ...
          ],
          "dependent_assets": [            # the components that depend on this vendor
            {"asset_name": "gpt-x", "kind": "model", "kind_label": "Model",
             "classification": "known", "classification_label": "Known", "managed": True},
            ...
          ],
          "gaps": ["…human-readable gap…", ...],
          "weakest_evidence": "vendor_asserted",  # softest evidence among assertions; None if none
          "posture_band": "elevated",             # ordinal risk band; never "secure"
          "summary": {
            "assertion_count": 3,
            "independently_evidenced": 1,
            "vendor_asserted": 2,          # assertions read as vendor-asserted / self-attested
            "gap_count": 2,
            "dependent_asset_count": 2,
            "unmanaged_dependencies": 0,
          },
        },
        ...
      ],
      "ungoverned_dependencies": [         # components with no vendor and/or unmanaged
        {"asset_name": "shadow-tool", "kind": "tool", "kind_label": "Tool",
         "classification": "unmanaged", "classification_label": "Unmanaged",
         "reason": "no_provider_and_unmanaged"},
        ...
      ],
      "summary": {
        "vendors": 2,
        "assertions_total": 5,
        "assertions_by_evidence_strength": {"technically_verified": 1, "vendor_asserted": 4},
        "independently_evidenced": 1,
        "vendor_asserted": 4,              # assertions read as vendor-asserted / self-attested
        "gaps": 4,
        "provider_less_dependencies": 1,
        "unmanaged_dependencies": 1,
        "worst_posture_band": "elevated",  # most concerning band across vendors; None if none
      },
    }
"""

from __future__ import annotations

from .graph_refs import in_graph
from .capability import RISK_BASELINE, RISK_ELEVATED, RISK_HIGH, _RISK_ORDER, _RISK_RAISED
from .models import (
    EvidenceClass,
    ProviderAssertion,
    evidence_strength,
)
from .governance import GOVERNED

# The classifications that make a component *managed* — a governed dependency.
# Anything else (unmanaged / unknown / high_risk / retired) is ungoverned, the
# same set :mod:`assurance.capability` treats as managed.
# The single definition, not a fourth private copy of it.
_MANAGED = GOVERNED

# The evidence-strength ordinals we key the honesty distinctions on. An assertion
# is "independently evidenced" only when its evidence is *stronger* than a bare
# vendor claim; at ``vendor_asserted`` strength or weaker it reads as a vendor
# claim. (Strongest → weakest is index 0 → N in EVIDENCE_STRENGTH_ORDER.)
_VENDOR_ASSERTED_RANK = evidence_strength(EvidenceClass.VENDOR_ASSERTED)
_CONTRACTUALLY_STATED_RANK = evidence_strength(EvidenceClass.CONTRACTUALLY_STATED)
_PARTIALLY_VERIFIED_RANK = evidence_strength(EvidenceClass.PARTIALLY_VERIFIED)

# Sources that are not independent of the vendor — the vendor's own word. An
# assertion from one of these is a gap even if it were labelled with a strong
# evidence class, so a self-declared claim never reads as independently evidenced.
_SELF_ATTESTED_SOURCES = {ProviderAssertion.Source.SELF_DECLARED}


def _is_independently_evidenced(evidence_class: str, source: str) -> bool:
    """True only when an assertion is backed by evidence stronger than a bare
    vendor claim *and* comes from a source that is not the vendor's own say-so. A
    ``vendor_asserted`` (or weaker) class, or a ``self_declared`` source, is never
    independently evidenced — that is the honesty this module exists to keep."""
    if source in _SELF_ATTESTED_SOURCES:
        return False
    return evidence_strength(evidence_class) < _VENDOR_ASSERTED_RANK


def _posture_from_evidence(weakest_evidence: str | None) -> str:
    """The base posture band from a vendor's *weakest* declared evidence. A vendor
    with nothing declared is the most concerning (``high``): silence is not
    assurance. A weaker profile is a higher band — the band is a concern signal
    reusing the capability module's risk vocabulary, never a grade or a pass."""
    if weakest_evidence is None:
        return RISK_HIGH
    rank = evidence_strength(weakest_evidence)
    if rank <= _CONTRACTUALLY_STATED_RANK:
        # technically / configuration verified, document-supported, contractually
        # stated — independently or documentarily backed.
        return RISK_BASELINE
    if rank <= _PARTIALLY_VERIFIED_RANK:
        # vendor-asserted or partially verified — the vendor's word, or a partial
        # check; a live gap to strengthen.
        return RISK_ELEVATED
    # unknown / not documented — nothing we can stand on.
    return RISK_HIGH


def _worst_band(a: str | None, b: str | None) -> str | None:
    """The more concerning of two posture bands (lowest RISK_ORDER index), either
    possibly None."""
    if a is None:
        return b
    if b is None:
        return a
    return a if _RISK_ORDER.index(a) <= _RISK_ORDER.index(b) else b


def _assertion_dict(assertion) -> dict:
    """One declared fact, evidence-graded, with its honest independence flag."""
    independently = _is_independently_evidenced(assertion.evidence_class, assertion.source)
    return {
        "field": assertion.field,
        "field_label": assertion.get_field_display(),
        "value": assertion.value,
        "evidence_class": assertion.evidence_class,
        "evidence_class_label": assertion.get_evidence_class_display(),
        "source": assertion.source,
        "source_label": assertion.get_source_display(),
        "independently_evidenced": independently,
        # A weak or self-attested fact is a gap — the profile's soft spot, surfaced.
        "gap": not independently,
    }


def _dependent_asset_dict(asset) -> dict:
    return {
        "asset_name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        "managed": asset.classification in _MANAGED,
    }


def _vendor_dict(provider, assets: list) -> dict:
    """One vendor's posture: what it asserts, at what strength, what depends on it,
    and an honest gap list and posture band. Never presents the vendor as secure."""
    assertions = sorted(provider.assertions.all(), key=lambda a: a.field)
    assertion_dicts = [_assertion_dict(a) for a in assertions]

    classes = [a.evidence_class for a in assertions]
    # The profile's weakest link: a vendor is only as evidenced as its softest
    # claim (max by strength ordinal = weakest).
    weakest = max(classes, key=evidence_strength) if classes else None

    dependent = sorted(assets, key=lambda a: (a.kind, a.name))
    dependent_dicts = [_dependent_asset_dict(a) for a in dependent]
    unmanaged = [d for d in dependent_dicts if not d["managed"]]

    gaps: list[str] = []
    if not assertions:
        gaps.append(
            "no assurance profile declared for this vendor — nothing is on record to assess"
        )
    for a in assertion_dicts:
        if a["gap"]:
            gaps.append(
                f"'{a['field_label']}' rests on {a['evidence_class_label'].lower()} "
                f"evidence ({a['source_label'].lower()}) — vendor-asserted, not "
                "independently evidenced"
            )
    for d in unmanaged:
        gaps.append(
            f"component '{d['asset_name']}' depends on this vendor but is "
            f"{d['classification_label'].lower()} — an unmanaged dependency"
        )

    # Base band from the weakest evidence; an unmanaged dependency raises it one
    # step (a shadow component on a vendor is a heavier concern than the profile
    # alone shows).
    posture = _posture_from_evidence(weakest)
    if unmanaged:
        posture = _RISK_RAISED[posture]

    return {
        "provider_uuid": str(provider.uuid),
        "provider_name": provider.name,
        "kind": provider.kind,
        "kind_label": provider.get_kind_display(),
        "region": provider.region,
        "assertions": assertion_dicts,
        "dependent_assets": dependent_dicts,
        "gaps": gaps,
        "weakest_evidence": weakest,
        "posture_band": posture,
        "summary": {
            "assertion_count": len(assertion_dicts),
            "independently_evidenced": sum(1 for a in assertion_dicts if a["independently_evidenced"]),
            "vendor_asserted": sum(1 for a in assertion_dicts if a["gap"]),
            "gap_count": len(gaps),
            "dependent_asset_count": len(dependent_dicts),
            "unmanaged_dependencies": len(unmanaged),
        },
    }


def assess_vendors(deployment) -> dict:
    """The third-party vendor assurance view for a deployment: each vendor its
    components depend on, what that vendor asserts and at what evidence strength,
    which components depend on it, an honest gap list, and an ordinal posture band.
    Prefetch ``assets__provider__assertions`` on the caller side. Pure and
    side-effect-free, deterministic, no timestamp.

    Never presents a vendor as secure or compliant: a ``vendor_asserted`` claim
    reads as vendor-asserted, and the posture band is a concern signal derived from
    the weakest evidence, not a grade. See the module docstring for the full return
    shape and honesty discipline."""
    # Group the deployment's components by the vendor they resolve to, and collect
    # the ungoverned ones (no vendor and/or unmanaged) as first-class gaps.
    by_provider: dict[int, dict] = {}
    ungoverned: list[dict] = []
    for asset in in_graph(deployment.assets.all()):
        managed = asset.classification in _MANAGED
        if asset.provider_id is None:
            # A dependency with no vendor behind it — provider-less, and doubly a
            # gap when it is also unmanaged. Surfaced, never dropped.
            reason = "no_provider_and_unmanaged" if not managed else "no_provider"
            ungoverned.append(
                {
                    "asset_name": asset.name,
                    "kind": asset.kind,
                    "kind_label": asset.get_kind_display(),
                    "classification": asset.classification,
                    "classification_label": asset.get_classification_display(),
                    "reason": reason,
                }
            )
            continue
        if not managed:
            ungoverned.append(
                {
                    "asset_name": asset.name,
                    "kind": asset.kind,
                    "kind_label": asset.get_kind_display(),
                    "classification": asset.classification,
                    "classification_label": asset.get_classification_display(),
                    "reason": "unmanaged",
                }
            )
        entry = by_provider.setdefault(asset.provider_id, {"provider": asset.provider, "assets": []})
        entry["assets"].append(asset)

    vendors = [_vendor_dict(entry["provider"], entry["assets"]) for entry in by_provider.values()]
    # Most concerning posture first, then most gaps, then name — a stable order.
    vendors.sort(
        key=lambda v: (_RISK_ORDER.index(v["posture_band"]), -v["summary"]["gap_count"], v["provider_name"])
    )

    ungoverned.sort(key=lambda u: (u["kind"], u["asset_name"]))

    # Roll-ups over every vendor assertion.
    by_strength: dict[str, int] = {}
    assertions_total = independently_total = vendor_asserted_total = gaps_total = 0
    worst_band = None
    for vendor in vendors:
        worst_band = _worst_band(worst_band, vendor["posture_band"])
        gaps_total += vendor["summary"]["gap_count"]
        for a in vendor["assertions"]:
            assertions_total += 1
            by_strength[a["evidence_class"]] = by_strength.get(a["evidence_class"], 0) + 1
            if a["independently_evidenced"]:
                independently_total += 1
            else:
                vendor_asserted_total += 1

    summary = {
        "vendors": len(vendors),
        "assertions_total": assertions_total,
        "assertions_by_evidence_strength": by_strength,
        "independently_evidenced": independently_total,
        "vendor_asserted": vendor_asserted_total,
        "gaps": gaps_total,
        "provider_less_dependencies": sum(1 for u in ungoverned if u["reason"].startswith("no_provider")),
        "unmanaged_dependencies": sum(1 for u in ungoverned if "unmanaged" in u["reason"]),
        "worst_posture_band": worst_band,
    }
    return {
        "vendors": vendors,
        "ungoverned_dependencies": ungoverned,
        "summary": summary,
    }
