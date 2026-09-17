"""Vertical Assurance Packs — the compliance map read through an industry lens.

A pack is a curated, code-only catalog entry: a name, a vertical, the control
**frameworks** it emphasizes, the regulatory regimes it targets, and the evidence
a buyer in that vertical expects to see. :func:`apply_pack` then computes a
deployment's coverage *through the lens of a pack* by reusing
:func:`assurance.compliance.build_compliance_map` and filtering it to the pack's
emphasized frameworks — it does not run a new assessment or define a new control
catalog.

The frameworks a pack emphasizes are the identifiers
:mod:`assurance.compliance` already defines (NIST SP 800-53, OWASP Top 10, OWASP
Top 10 for LLM Applications, DoD Zero Trust). The catalog is **not** redefined
here; a pack only names which of those existing frameworks matter for its
vertical.

Honest about the difference between a framework we compute and a regime we do not:

- A pack's ``frameworks`` are the ones the compliance map actually itemises as
  controls, so ``apply_pack`` reports real coverage against them.
- A pack's ``regulatory_regimes`` (HIPAA, PCI-DSS, SOX, FedRAMP, NIST AI RMF) are
  the industry regimes the vertical answers to. Athena does **not** hold a control
  catalog for these, so they are carried as **context, not computed coverage** —
  surfaced with an explicit note rather than faked into controls we cannot score.

And it keeps the compliance map's core honesty: a control a finding **touched** is
a control with an open finding against it — a **gap**, never "passed" and never
"compliant". A pack narrows the lens; it never turns a touched control into a
satisfied one. Nothing here claims a deployment is compliant with a regime.

Computed on read (a pure function over the compliance map, which is itself a pure
function of ``deployment.findings.all()``) — no new record, no migration, no
timestamp. Prefetch ``findings`` on the caller side to keep it query-light.
"""

from __future__ import annotations

from .compliance import (
    FRAMEWORK_DOD_ZT,
    FRAMEWORK_NIST,
    FRAMEWORK_OWASP,
    FRAMEWORK_OWASP_LLM,
    _FRAMEWORK_NAMES,
    build_compliance_map,
)


class UnknownPack(ValueError):
    """An unknown pack key. A caller turns this into a clean 400 rather than
    guessing a pack, mirroring how :class:`assurance.remediation.IllegalTransition`
    signals a bad key elsewhere in the assurance layer."""


# ---------------------------------------------------------------------------
# The pack catalog (module data — no DB, no redefined framework catalog)
# ---------------------------------------------------------------------------

# Each pack names the compliance-map frameworks it emphasizes (by the identifiers
# compliance.py already defines), the regulatory regimes it answers to (context we
# do not itemise as controls), and the evidence a buyer in that vertical expects.
_PACKS: tuple[dict, ...] = (
    {
        "key": "healthcare",
        "name": "Healthcare (HIPAA + NIST 800-53)",
        "vertical": "healthcare",
        "description": (
            "For AI systems handling protected health information. Emphasizes "
            "NIST SP 800-53 technical safeguards, read alongside the HIPAA Security "
            "Rule; adds the OWASP LLM Top 10 where the system is model-driven."
        ),
        "frameworks": (FRAMEWORK_NIST, FRAMEWORK_OWASP_LLM),
        "regulatory_regimes": ("HIPAA",),
        "evidence_expectations": (
            "Access enforcement and least privilege on PHI stores (NIST AC family).",
            "Transmission and at-rest cryptographic protection (NIST SC family).",
            "Audit logging of PHI access sufficient for an accounting of disclosures.",
            "A Business Associate Agreement on file for every provider that touches PHI.",
        ),
    },
    {
        "key": "financial-services",
        "name": "Financial services (PCI-DSS, SOX, NIST)",
        "vertical": "financial_services",
        "description": (
            "For AI systems in payment, trading or financial-reporting paths. "
            "Emphasizes NIST SP 800-53 and the OWASP Top 10 for the web surface, "
            "read alongside PCI-DSS (cardholder data) and SOX (financial-reporting "
            "integrity)."
        ),
        "frameworks": (FRAMEWORK_NIST, FRAMEWORK_OWASP),
        "regulatory_regimes": ("PCI-DSS", "SOX"),
        "evidence_expectations": (
            "Network segmentation and boundary protection around cardholder data (NIST SC-7).",
            "Strong authentication and least privilege on financial functions (NIST AC/IA).",
            "Change-integrity and audit controls supporting SOX financial-reporting assertions.",
            "No injection or broken-access-control findings on the payment surface (OWASP A01/A03).",
        ),
    },
    {
        "key": "federal",
        "name": "Federal / government (FedRAMP, DoD Zero Trust, NIST 800-53)",
        "vertical": "federal_government",
        "description": (
            "For AI systems seeking a federal authorization. Emphasizes NIST SP "
            "800-53 and the DoD Zero Trust pillars, read alongside FedRAMP (which "
            "baselines on NIST 800-53)."
        ),
        "frameworks": (FRAMEWORK_DOD_ZT, FRAMEWORK_NIST),
        "regulatory_regimes": ("FedRAMP",),
        "evidence_expectations": (
            "Coverage across the seven DoD Zero Trust pillars (user, device, data, ...).",
            "A NIST 800-53 control baseline appropriate to the FedRAMP impact level.",
            "Continuous monitoring and visibility over the deployment (NIST CA/AU, ZT visibility).",
            "Boundary and information-flow enforcement between trust zones (NIST SC-7/AC-4).",
        ),
    },
    {
        "key": "general-ai",
        "name": "General AI (OWASP LLM Top 10, NIST AI RMF)",
        "vertical": "general_ai",
        "description": (
            "The default lens for any AI system. Emphasizes the OWASP Top 10 for "
            "LLM Applications and the OWASP Top 10 for the surrounding web surface, "
            "read alongside the NIST AI Risk Management Framework."
        ),
        "frameworks": (FRAMEWORK_OWASP_LLM, FRAMEWORK_OWASP),
        "regulatory_regimes": ("NIST AI RMF",),
        "evidence_expectations": (
            "No open prompt-injection or insecure-output-handling findings (OWASP LLM01/LLM05).",
            "Bounded agency and least privilege on tools the model can call (OWASP LLM06).",
            "Supply-chain and sensitive-information-disclosure risks assessed (OWASP LLM02/LLM03).",
            "A documented mapping of the system's risks to the NIST AI RMF functions.",
        ),
    },
)

_PACKS_BY_KEY = {pack["key"]: pack for pack in _PACKS}

# The note attached to a regulatory regime, so a consumer never mistakes it for
# computed coverage — it is the vertical's context, not a control we can score.
_REGIME_NOTE = (
    "Regulatory context for this vertical. Athena holds no itemised control "
    "catalog for this regime, so it is surfaced as context, not computed coverage."
)


def _pack_public(pack: dict) -> dict:
    """The catalog view of a pack: its identity, the frameworks it emphasizes (with
    their names), the regimes it answers to, and the evidence expectations. Lists
    are materialised so the payload is JSON-safe and independent of the tuples."""
    return {
        "key": pack["key"],
        "name": pack["name"],
        "vertical": pack["vertical"],
        "description": pack["description"],
        "frameworks": list(pack["frameworks"]),
        "framework_names": {fw: _FRAMEWORK_NAMES[fw] for fw in pack["frameworks"]},
        "regulatory_regimes": list(pack["regulatory_regimes"]),
        "evidence_expectations": list(pack["evidence_expectations"]),
    }


def list_packs() -> dict:
    """The full vertical assurance pack catalog — code constants, no DB. Each entry
    names the compliance frameworks it emphasizes (by the identifiers compliance.py
    already defines), the regulatory regimes it targets, and the evidence a buyer in
    that vertical expects. Deterministic and side-effect-free."""
    packs = [_pack_public(p) for p in _PACKS]
    return {"packs": packs, "summary": {"packs": len(packs)}}


def apply_pack(deployment, pack_key: str) -> dict:
    """A deployment's compliance coverage read through the lens of one pack.

    Reuses :func:`assurance.compliance.build_compliance_map` and filters it to the
    pack's emphasized frameworks — it computes no new controls and defines no new
    catalog. Coverage is reported honestly: a control a finding **touched** is a
    control with an open finding against it — a gap, never "passed" and never
    "compliant". The pack's regulatory regimes are carried as context, never as
    computed coverage. Prefetch ``findings`` on the caller side.

    Raises :class:`UnknownPack` for an unrecognised ``pack_key``."""
    pack = _PACKS_BY_KEY.get(pack_key)
    if pack is None:
        raise UnknownPack(
            f"Unknown assurance pack: {pack_key!r}. "
            f"Known packs: {sorted(_PACKS_BY_KEY)}."
        )

    compliance = build_compliance_map(deployment)
    emphasized = set(pack["frameworks"])
    # Keep the compliance map's own framework slices, in its order, for the
    # frameworks this pack emphasizes — a filter, not a recomputation.
    frameworks = [fw for fw in compliance["frameworks"] if fw["key"] in emphasized]

    controls_touched = sum(fw["summary"]["controls_touched"] for fw in frameworks)
    controls_with_active = sum(fw["summary"]["controls_with_active_findings"] for fw in frameworks)
    worst = _worst_across(fw["summary"]["worst_severity"] for fw in frameworks)

    regimes = [{"name": name, "note": _REGIME_NOTE} for name in pack["regulatory_regimes"]]

    return {
        "pack": _pack_public(pack),
        # The emphasized frameworks' compliance slices, verbatim from the map (a
        # touched control is an open gap, carried through unchanged).
        "frameworks": frameworks,
        "regulatory_regimes": regimes,
        "summary": {
            "frameworks_emphasized": len(frameworks),
            "controls_touched": controls_touched,
            "controls_with_active_findings": controls_with_active,
            "worst_severity": worst,
            # The finding totals are the deployment's, carried from the compliance
            # map so the pack view is honest about the whole finding set it filtered.
            "total_findings": compliance["summary"]["total_findings"],
            "active_findings": compliance["summary"]["active_findings"],
            "resolved_findings": compliance["summary"]["resolved_findings"],
            "unmapped_finding_types": compliance["summary"]["unmapped_finding_types"],
        },
    }


def _worst_across(severities) -> str | None:
    """The worst of an iterable of severities (each possibly None). Local import of
    the severity rank keeps the module's only model dependency in one place."""
    from .models import severity_rank

    worst = None
    for sev in severities:
        if sev is None:
            continue
        if worst is None or severity_rank(sev) > severity_rank(worst):
            worst = sev
    return worst
