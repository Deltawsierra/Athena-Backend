"""Business-impact map — which business-impact *dimensions* a deployment's findings
implicate, and how heavily (Phase 2.4).

The roadmap frames this view as "finding → business process → owner →
financial / regulatory / customer impact": the language executives renew on. This
module is the honest first course of that map. It is a computed aggregation over
findings that already exist — it runs no new scan, builds no model, and stores no
record. It takes each finding a deployment already carries and maps it onto the
business-impact **dimensions** its finding type implies, weighted by severity, so a
reader can see where a portfolio of findings concentrates its *potential* business
consequence.

Read every field here as **inferred, potential exposure from finding type and
severity — never a realized loss.** Nothing in this module is a dollar figure, an
actuarial estimate, or a claim that the business *was* harmed. It does not measure
money lost, customers churned, or a fine levied; it says only, from a finding's
*type* and *severity*, which *kinds* of business consequence that finding could
bear on, and at what ordinal band. The deliberate vocabulary reflects that: a
dimension is *implicated* by a finding, never *quantified*; a dimension carries an
ordinal **exposure band** (``elevated`` / ``moderate`` / ``low``), never an amount
and never a currency. A reader who wants a number will not find one here, by
design — turning a finding type into a dollar loss would be a fabrication, not an
assessment.

**Dimensions and owners — but not invented processes.** The roadmap's full chain
runs finding → business *process* → *owner* → impact. This module maps to impact
**dimensions** and attributes potential exposure to the **owner** accountable for
each finding — the finding's ``owner`` FK, the person who dispositions it. That
ownership is *declared data we hold*, so attributing "whose impact" to it is honest
rather than a guess: a finding with no owner rolls up to an explicit
``(unassigned)`` bucket, never onto a person, and an owner's band is the same
ordinal exposure band the dimensions use. What is still NOT produced is per-
*process* attribution: the finding model carries no business-process field and no
process→owner map, so inventing one would be dishonest. That remains a deliberate
future extension requiring *declared* business context (a process catalog, a
data-classification of what each process handles) a customer supplies. Note the
owner here is the finding's disposition owner, not the owner *of an affected
business process* — the map is honest about attributing to the former, not the
latter.

It is honest in the same three ways the rest of the assurance layer is:

- **Only active findings are open exposure.** A finding that is verified-closed,
  accepted as risk, or a false positive is resolved (see
  :mod:`assurance.decision`) and no longer counts toward active exposure. It MAY
  still be listed against the dimension it historically implicated, with a zero
  active count and no exposure band, so the history is visible rather than erased.
- **Nothing is silently dropped.** A ``finding_type`` whose type implies no
  business-impact dimension is surfaced explicitly in ``unmapped`` — a coverage gap
  in the *map itself*, admitted, not fudged into a dimension it does not belong to.
- **The band is ordinal, derived from evidence.** A dimension's exposure band is a
  function of the worst *active* severity landing on it and how many active
  findings do — a concentration signal, an ordinal ``elevated``/``moderate``/``low``
  band, never a score and never money.

Computed on read (a pure function of ``deployment.findings.all()``), like
:func:`assurance.compliance.build_compliance_map` and
:func:`assurance.capability.assess_capabilities` — no new record, no migration, no
timestamp in the payload. Prefetch ``findings`` on the caller side to keep it
query-light.

The return shape of :func:`build_business_impact`::

    {
      "dimensions": [                     # one per implicated dimension, worst-first
        {
          "key": "data_confidentiality",
          "label": "Data confidentiality",
          "description": "...",           # what this dimension means
          "active_finding_count": 2,      # open findings implicating this dimension
          "resolved_finding_count": 1,    # historically implicated, now resolved
          "worst_severity": "high",       # worst among ACTIVE findings; None if none active
          "exposure_band": "elevated",    # ordinal band from worst severity + count; None if none active
          "finding_types": ["data_boundary_violation", "sql_injection"],  # sorted, distinct
        },
        ...
      ],
      "unmapped": [                        # finding_types implying no dimension
        {
          "finding_type": "some_new_type",
          "active_finding_count": 1,
          "resolved_finding_count": 0,
          "worst_severity": "medium",      # worst among active; None if none active
        },
        ...
      ],
      "owners": [                          # whose impact — worst-attributed-first
        {
          "owner": {                       # the accountable disposition owner, or
            "known": true,                 # {"known": false, ...} for the unassigned bucket
            "id": 5,
            "username": "alice",
            "label": "alice",              # "(unassigned)" when unknown — never a guess
          },
          "active_finding_count": 2,
          "resolved_finding_count": 0,
          "worst_severity": "high",        # worst among this owner's ACTIVE findings; None if none
          "exposure_band": "elevated",     # same ordinal band the dimensions use; None if none active
          "dimensions": ["customer_trust", "data_confidentiality"],  # sorted keys implicated
          "finding_types": ["sql_injection"],                        # sorted, distinct
        },
        ...
      ],
      "summary": {
        "total_findings": 7,
        "active_findings": 5,
        "resolved_findings": 2,
        "mapped_finding_types": 4,             # distinct types implicating >=1 dimension
        "unmapped_finding_types": 1,
        "dimensions": 6,                       # size of the curated dimension vocabulary
        "dimensions_touched": 5,               # dimensions with >=1 finding (any status)
        "dimensions_with_active_exposure": 4,  # dimensions with >=1 active finding
        "worst_severity": "critical",          # worst active across every dimension; None if none
        "worst_exposure_band": "elevated",     # strongest band across dimensions; None if none active
        "owners_attributed": 2,                # distinct KNOWN owners carrying any exposure
        "owners_with_active_exposure": 2,      # known owners with >=1 active finding
        "findings_without_owner": 1,           # findings with no owner (an attribution gap, not zero impact)
      },
    }
"""

from __future__ import annotations

from .models import (
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_ORDER,
    Finding,
    severity_rank,
)

# Findings in these states are resolved — no longer active exposure. Mirrors
# ``assurance.decision._RESOLVED_STATUSES`` and ``assurance.compliance`` so every
# view agrees on what "active" means. A resolved finding may still be listed
# against the dimension it historically implicated, with a zero active count and
# no exposure band.
_RESOLVED_STATUSES = frozenset(
    {Finding.Status.CLOSED, Finding.Status.ACCEPTED, Finding.Status.FALSE_POSITIVE}
)

# ---------------------------------------------------------------------------
# Business-impact dimensions (curated module data)
# ---------------------------------------------------------------------------

DIMENSION_FINANCIAL = "financial"
DIMENSION_REGULATORY = "regulatory"
DIMENSION_CUSTOMER_TRUST = "customer_trust"
DIMENSION_OPERATIONAL = "operational"
DIMENSION_DATA_CONFIDENTIALITY = "data_confidentiality"
DIMENSION_SAFETY = "safety"

# The curated dimensions, in a stable reporting order (used only as a sort
# tie-break — the live order is worst-exposure-first). Each carries a label and a
# description worded as *potential* consequence, never a realized one.
_DIMENSIONS = (
    (
        DIMENSION_FINANCIAL,
        "Financial exposure",
        (
            "Potential for direct monetary exposure — resource-cost abuse or "
            "fraud-enabling weakness inferred from the finding type. Not a loss figure."
        ),
    ),
    (
        DIMENSION_REGULATORY,
        "Regulatory exposure",
        (
            "Potential exposure under data-protection, audit or sector regimes — a "
            "confidentiality, transport-security or audit-trail weakness a regulator "
            "would care about. Not a finding of non-compliance or a fine."
        ),
    ),
    (
        DIMENSION_CUSTOMER_TRUST,
        "Customer trust",
        (
            "Potential erosion of customer or end-user trust — user-facing compromise, "
            "account takeover, or a breach of data customers entrusted. Not measured churn."
        ),
    ),
    (
        DIMENSION_OPERATIONAL,
        "Operational continuity",
        (
            "Potential disruption to service continuity or configuration hygiene — "
            "availability, exposed surface, or misconfiguration. Not observed downtime."
        ),
    ),
    (
        DIMENSION_DATA_CONFIDENTIALITY,
        "Data confidentiality",
        (
            "Potential loss of data confidentiality — unauthorized read or exfiltration "
            "of data the finding type could expose. Not a confirmed breach."
        ),
    ),
    (
        DIMENSION_SAFETY,
        "Safety of autonomous action",
        (
            "Potential for unsafe or harmful action — agentic overreach, code or command "
            "execution, or model-integrity harm that could drive a damaging action or "
            "output. Not an observed harm."
        ),
    ),
)
_DIMENSION_LABELS = {key: label for key, label, _ in _DIMENSIONS}
_DIMENSION_DESCRIPTIONS = {key: desc for key, _, desc in _DIMENSIONS}
# The stable index of a dimension key, for sort tie-breaks.
_DIMENSION_ORDER = {key: i for i, (key, _, _) in enumerate(_DIMENSIONS)}

# ---------------------------------------------------------------------------
# Ordinal exposure bands
# ---------------------------------------------------------------------------

# Ordinal exposure bands, strongest concern first. A band is NOT a score and NOT a
# currency — it is an ordinal signal of how concentrated a dimension's *potential*
# exposure is, derived from the worst active severity landing on it and how many
# active findings do.
BAND_ELEVATED = "elevated"
BAND_MODERATE = "moderate"
BAND_LOW = "low"
_BAND_ORDER = (BAND_ELEVATED, BAND_MODERATE, BAND_LOW)  # index 0 = strongest
_BAND_RAISED = {BAND_LOW: BAND_MODERATE, BAND_MODERATE: BAND_ELEVATED, BAND_ELEVATED: BAND_ELEVATED}

# This many active findings on one dimension raise its band one step: a
# concentration of open findings is a heavier potential exposure than a single one
# of the same severity. Ordinal, deliberate, not a threshold on any amount.
_BAND_ESCALATION_COUNT = 3


def _band_rank(band: str | None) -> int:
    """A sortable rank for an exposure band; a dimension with no active exposure
    (band None) sorts last."""
    return _BAND_ORDER.index(band) if band else len(_BAND_ORDER)


def _exposure_band(worst_active_rank: int, active_count: int) -> str | None:
    """The ordinal exposure band for a dimension, from the worst *active* severity
    landing on it and how many active findings do. None when nothing is active — a
    resolved-only dimension is not open exposure, so it carries no band. Never a
    number, never a currency."""
    if active_count <= 0 or worst_active_rank < 0:
        return None
    if worst_active_rank >= severity_rank(SEVERITY_HIGH):
        band = BAND_ELEVATED
    elif worst_active_rank >= severity_rank(SEVERITY_MEDIUM):
        band = BAND_MODERATE
    else:
        band = BAND_LOW
    # A concentration of open findings raises the band one step.
    if active_count >= _BAND_ESCALATION_COUNT:
        band = _BAND_RAISED[band]
    return band


# ---------------------------------------------------------------------------
# finding_type → business-impact dimensions (curated crosswalk, module data)
# ---------------------------------------------------------------------------

# The curated crosswalk. Each finding_type maps to the business-impact dimensions
# its *type* implies — the kinds of business consequence a finding of that type
# could bear on, not a measured impact. It covers the same finding-type vocabulary
# :mod:`assurance.compliance` maps. A type outside this table is surfaced honestly
# in ``unmapped`` rather than forced onto a dimension it does not belong to.
#
# Note that many types deliberately do NOT carry the ``financial`` dimension:
# inferring a monetary consequence from, say, a missing security header would read
# as a quantified loss this module refuses to assert. ``financial`` is reserved for
# types whose *nature* is direct cost or fraud exposure (e.g. resource-cost abuse).
_FINDING_TYPE_DIMENSIONS: dict[str, tuple[str, ...]] = {
    # Injection / data-exposure web findings.
    "sql_injection": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_REGULATORY, DIMENSION_CUSTOMER_TRUST),
    "sqli": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_REGULATORY, DIMENSION_CUSTOMER_TRUST),
    "xss": (DIMENSION_CUSTOMER_TRUST, DIMENSION_OPERATIONAL),
    "csrf": (DIMENSION_CUSTOMER_TRUST, DIMENSION_OPERATIONAL),
    "cors_misconfiguration": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_OPERATIONAL),
    "command_injection": (DIMENSION_OPERATIONAL, DIMENSION_SAFETY),
    "directory_traversal": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_REGULATORY),
    "header_injection": (DIMENSION_OPERATIONAL, DIMENSION_CUSTOMER_TRUST),
    "missing_security_header": (DIMENSION_OPERATIONAL,),
    "misconfiguration": (DIMENSION_OPERATIONAL,),
    "security_misconfiguration": (DIMENSION_OPERATIONAL,),
    "insecure_cookie": (DIMENSION_CUSTOMER_TRUST, DIMENSION_DATA_CONFIDENTIALITY),
    "ssl_error": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_REGULATORY),
    "auth_bruteforce": (DIMENSION_CUSTOMER_TRUST, DIMENSION_OPERATIONAL),
    "endpoint_exposed": (DIMENSION_OPERATIONAL, DIMENSION_DATA_CONFIDENTIALITY),
    "ssrf": (DIMENSION_OPERATIONAL, DIMENSION_DATA_CONFIDENTIALITY),
    "sensitive_data_exposure": (
        DIMENSION_DATA_CONFIDENTIALITY,
        DIMENSION_REGULATORY,
        DIMENSION_CUSTOMER_TRUST,
    ),
    "insecure_deserialization": (DIMENSION_OPERATIONAL, DIMENSION_SAFETY),
    "vulnerable_component": (DIMENSION_OPERATIONAL,),
    "outdated_component": (DIMENSION_OPERATIONAL,),
    "missing_logging": (DIMENSION_REGULATORY, DIMENSION_OPERATIONAL),
    # LLM / AI-native finding types.
    "prompt_injection": (DIMENSION_SAFETY, DIMENSION_DATA_CONFIDENTIALITY),
    "sensitive_information_disclosure": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_REGULATORY),
    "insecure_output_handling": (DIMENSION_OPERATIONAL, DIMENSION_SAFETY),
    "excessive_agency": (DIMENSION_OPERATIONAL, DIMENSION_SAFETY),
    "excessive_permission": (DIMENSION_OPERATIONAL, DIMENSION_SAFETY),
    "system_prompt_leakage": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_OPERATIONAL),
    "data_poisoning": (DIMENSION_SAFETY, DIMENSION_CUSTOMER_TRUST),
    "model_poisoning": (DIMENSION_SAFETY, DIMENSION_CUSTOMER_TRUST),
    "vector_weakness": (DIMENSION_DATA_CONFIDENTIALITY, DIMENSION_SAFETY),
    "misinformation": (DIMENSION_CUSTOMER_TRUST, DIMENSION_SAFETY),
    "unbounded_consumption": (DIMENSION_OPERATIONAL, DIMENSION_FINANCIAL),
    "supply_chain": (DIMENSION_OPERATIONAL, DIMENSION_SAFETY),
    # Boundary / capability-derived finding types.
    "shadow_component": (DIMENSION_OPERATIONAL, DIMENSION_DATA_CONFIDENTIALITY),
    "data_boundary_violation": (
        DIMENSION_DATA_CONFIDENTIALITY,
        DIMENSION_REGULATORY,
        DIMENSION_CUSTOMER_TRUST,
    ),
}


def _dimensions_for(finding_type: str) -> tuple[str, ...]:
    """The curated business-impact dimensions a finding type implies. Case- and
    whitespace-insensitive on the type. Empty when the type is not in the crosswalk
    — the caller then surfaces it as unmapped rather than guessing a dimension."""
    return _FINDING_TYPE_DIMENSIONS.get((finding_type or "").strip().lower(), ())


# ---------------------------------------------------------------------------
# Accumulators
# ---------------------------------------------------------------------------


class _Dimension:
    """One business-impact dimension, accumulating the findings whose type implies
    it. 'Implicated' is inferred *potential* exposure, never a realized loss."""

    def __init__(self, key: str):
        self.key = key
        self.active = 0
        self.resolved = 0
        self._worst_active_rank = -1
        self.finding_types: set[str] = set()

    def add(self, *, active: bool, severity: str, finding_type: str) -> None:
        if active:
            self.active += 1
            rank = severity_rank(severity)
            if rank > self._worst_active_rank:
                self._worst_active_rank = rank
        else:
            self.resolved += 1
        if finding_type:
            self.finding_types.add(finding_type)

    @property
    def worst_severity(self) -> str | None:
        # Worst severity among ACTIVE findings only — a resolved-only dimension is
        # not open exposure, so it has no worst severity.
        return SEVERITY_ORDER[self._worst_active_rank] if self._worst_active_rank >= 0 else None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": _DIMENSION_LABELS[self.key],
            "description": _DIMENSION_DESCRIPTIONS[self.key],
            "active_finding_count": self.active,
            "resolved_finding_count": self.resolved,
            "worst_severity": self.worst_severity,
            "exposure_band": _exposure_band(self._worst_active_rank, self.active),
            "finding_types": sorted(self.finding_types),
        }


class _Owner:
    """One owner accountable for a set of findings, accumulating the *potential*
    business exposure attributed to them — answering "whose impact". The owner is
    the finding's ``owner`` FK (the person accountable for its disposition). An
    unknown owner is an explicit ``(unassigned)`` bucket, never guessed onto a
    person."""

    def __init__(self, owner_id, *, username=None):
        self.owner_id = owner_id
        self.username = username
        self.active = 0
        self.resolved = 0
        self._worst_active_rank = -1
        self.dimensions: set[str] = set()
        self.finding_types: set[str] = set()

    @property
    def known(self) -> bool:
        return self.owner_id is not None

    def add(self, *, active: bool, severity: str, finding_type: str, dimensions: tuple[str, ...]) -> None:
        if active:
            self.active += 1
            rank = severity_rank(severity)
            if rank > self._worst_active_rank:
                self._worst_active_rank = rank
        else:
            self.resolved += 1
        if finding_type:
            self.finding_types.add(finding_type)
        self.dimensions.update(dimensions)

    @property
    def worst_severity(self) -> str | None:
        return SEVERITY_ORDER[self._worst_active_rank] if self._worst_active_rank >= 0 else None

    def to_dict(self) -> dict:
        return {
            "owner": {
                "known": self.known,
                "id": self.owner_id,
                # Honest label: the accountable person, or an explicit "unassigned"
                # when no owner is set — never a guessed attribution.
                "username": self.username if self.known else None,
                "label": self.username if self.known else "(unassigned)",
            },
            "active_finding_count": self.active,
            "resolved_finding_count": self.resolved,
            "worst_severity": self.worst_severity,
            "exposure_band": _exposure_band(self._worst_active_rank, self.active),
            # The dimensions this owner's findings implicate (mapped only), sorted.
            "dimensions": sorted(self.dimensions),
            "finding_types": sorted(self.finding_types),
        }


class _Unmapped:
    """A finding_type that implies no curated dimension — a gap in the map itself,
    surfaced rather than dropped."""

    def __init__(self, finding_type: str):
        self.finding_type = finding_type
        self.active = 0
        self.resolved = 0
        self._worst_active_rank = -1

    def add(self, *, active: bool, severity: str) -> None:
        if active:
            self.active += 1
            rank = severity_rank(severity)
            if rank > self._worst_active_rank:
                self._worst_active_rank = rank
        else:
            self.resolved += 1

    def to_dict(self) -> dict:
        worst = SEVERITY_ORDER[self._worst_active_rank] if self._worst_active_rank >= 0 else None
        return {
            "finding_type": self.finding_type,
            "active_finding_count": self.active,
            "resolved_finding_count": self.resolved,
            "worst_severity": worst,
        }


def _worst(a: str | None, b: str | None) -> str | None:
    """The worse of two severities, either possibly None (no active finding)."""
    if a is None:
        return b
    if b is None:
        return a
    return a if severity_rank(a) >= severity_rank(b) else b


# ---------------------------------------------------------------------------
# The map
# ---------------------------------------------------------------------------


def build_business_impact(deployment) -> dict:
    """The business-impact map for a deployment: which business-impact *dimensions*
    its findings implicate, how heavily (an ordinal band, never an amount), which
    finding types imply no dimension, and — the "whose impact" view — the potential
    exposure attributed to each accountable owner. Prefetch ``findings`` and
    select_related ``owner`` on the caller side. Pure and side-effect-free,
    deterministic, no timestamp.

    This is **inferred potential exposure from finding type and severity — never a
    realized loss, never a dollar figure, never a claim the business was harmed.**
    Owner attribution is grounded in the finding's ``owner`` FK (the person
    accountable for its disposition) — it is *real, declared ownership*, not a
    guess; a finding with no owner rolls up to an explicit ``(unassigned)`` bucket,
    never onto a person. Per-*process* attribution is still not produced: the model
    carries no business-process field, so inventing one would be dishonest. See the
    module docstring for the full return shape and honesty discipline."""
    dimensions: dict[str, _Dimension] = {}
    unmapped: dict[str, _Unmapped] = {}
    owners: dict[object, _Owner] = {}

    total = active_total = resolved_total = 0
    without_owner = 0
    mapped_types: set[str] = set()

    def ensure(key: str) -> _Dimension:
        dim = dimensions.get(key)
        if dim is None:
            dim = _Dimension(key)
            dimensions[key] = dim
        return dim

    def ensure_owner(owner) -> _Owner:
        owner_id = owner.pk if owner is not None else None
        entry = owners.get(owner_id)
        if entry is None:
            entry = _Owner(owner_id, username=(owner.get_username() if owner is not None else None))
            owners[owner_id] = entry
        return entry

    for finding in deployment.findings.all():
        total += 1
        is_active = finding.status not in _RESOLVED_STATUSES
        if is_active:
            active_total += 1
        else:
            resolved_total += 1
        ftype = (finding.finding_type or "").strip()

        keys = _dimensions_for(finding.finding_type)
        if keys:
            # The crosswalk lookup is case-insensitive (_dimensions_for lowercases),
            # so dedup the distinct-type count the same way — otherwise
            # "SQL_Injection" and "sql_injection" double-count as two mapped types.
            mapped_types.add(ftype.lower())
            for key in keys:
                ensure(key).add(active=is_active, severity=finding.severity, finding_type=ftype)
        else:
            # No dimension — surfaced honestly as an unmapped type, keyed by the type
            # so many findings of one type roll up to one entry.
            key = ftype or "(unspecified)"
            entry = unmapped.get(key)
            if entry is None:
                entry = _Unmapped(key)
                unmapped[key] = entry
            entry.add(active=is_active, severity=finding.severity)

        # Whose impact: attribute this finding to its accountable owner (the
        # ``owner`` FK), or to the explicit "(unassigned)" bucket. The owner
        # carries the same dimensions this finding implicates (mapped only).
        owner = getattr(finding, "owner", None)
        if owner is None:
            without_owner += 1
        ensure_owner(owner).add(
            active=is_active, severity=finding.severity, finding_type=ftype, dimensions=keys
        )

    dimension_list = [d.to_dict() for d in dimensions.values()]
    # Strongest potential exposure first: by exposure band, then worst active
    # severity, then most open findings, then the curated dimension order — a
    # deterministic, stable sort.
    dimension_list.sort(
        key=lambda d: (
            _band_rank(d["exposure_band"]),
            -severity_rank(d["worst_severity"]) if d["worst_severity"] else 1,
            -d["active_finding_count"],
            _DIMENSION_ORDER[d["key"]],
        )
    )

    unmapped_list = [u.to_dict() for u in unmapped.values()]
    # Worst active first, then most active, then type name — a stable order,
    # matching the compliance map's unmapped ordering.
    unmapped_list.sort(
        key=lambda u: (
            -severity_rank(u["worst_severity"]) if u["worst_severity"] else 1,
            -u["active_finding_count"],
            u["finding_type"],
        )
    )

    owner_list = [o.to_dict() for o in owners.values()]
    # Strongest attributed exposure first: by band, then worst active severity,
    # then most open findings; a KNOWN owner sorts before the "(unassigned)" bucket
    # at equal exposure, then by label — a deterministic, stable order.
    owner_list.sort(
        key=lambda o: (
            _band_rank(o["exposure_band"]),
            -severity_rank(o["worst_severity"]) if o["worst_severity"] else 1,
            -o["active_finding_count"],
            not o["owner"]["known"],
            o["owner"]["label"],
        )
    )

    overall_worst = None
    overall_band_rank = len(_BAND_ORDER)
    with_active = 0
    for dim in dimension_list:
        if dim["active_finding_count"] > 0:
            with_active += 1
            overall_worst = _worst(overall_worst, dim["worst_severity"])
            overall_band_rank = min(overall_band_rank, _band_rank(dim["exposure_band"]))
    worst_band = _BAND_ORDER[overall_band_rank] if overall_band_rank < len(_BAND_ORDER) else None

    owners_attributed = sum(1 for o in owner_list if o["owner"]["known"])
    owners_with_active = sum(
        1 for o in owner_list if o["owner"]["known"] and o["active_finding_count"] > 0
    )

    summary = {
        "total_findings": total,
        "active_findings": active_total,
        "resolved_findings": resolved_total,
        "mapped_finding_types": len(mapped_types),
        "unmapped_finding_types": len(unmapped_list),
        "dimensions": len(_DIMENSIONS),
        "dimensions_touched": len(dimension_list),
        "dimensions_with_active_exposure": with_active,
        "worst_severity": overall_worst,
        "worst_exposure_band": worst_band,
        # Whose impact: how many distinct known owners carry attributed exposure,
        # and how many findings have no owner (an honest attribution gap, not zero
        # impact).
        "owners_attributed": owners_attributed,
        "owners_with_active_exposure": owners_with_active,
        "findings_without_owner": without_owner,
    }
    return {
        "dimensions": dimension_list,
        "unmapped": unmapped_list,
        "owners": owner_list,
        "summary": summary,
    }
