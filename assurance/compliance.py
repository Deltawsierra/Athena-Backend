"""Compliance mapping — where a deployment's findings land against control frameworks (Phase 2.1).

A computed layer over findings that already exist. It runs no new scan and proves
no control: it takes each finding a deployment already carries and maps it onto the
control frameworks a customer's procurement and audit teams speak — NIST SP 800-53
Rev 5, the OWASP Top 10 (2021), the OWASP Top 10 for LLM Applications (2025), and
the DoD Zero Trust pillars — so a reader can see, honestly, where the evidence
lands and where it does not.

It is evidence of **gaps**, never a certificate of compliance. A control that a
finding touches is a control the deployment has an **open finding against** — that
is the opposite of a passing control. So the vocabulary here is deliberate: a
control is *touched by a finding*, never *satisfied*; the per-framework roll-up
reports *controls with active findings*, never *controls met*. Nothing in this
module ever asserts a control passes; absence of a finding is not evidence of
coverage, and the map does not claim it is.

It is honest in the same three ways the rest of the assurance layer is:

- **Only active findings are open gaps.** A finding that is verified-closed,
  accepted as risk, or a false positive is resolved (see
  :mod:`assurance.decision`); it no longer counts toward an open control gap. It
  MAY still be listed against the control it historically touched, with a zero
  active count, so the history is visible rather than erased.
- **Nothing is silently dropped.** A ``finding_type`` that maps to no control in
  any framework is surfaced explicitly in ``unmapped`` — a coverage gap in the
  *map itself*, admitted, not fudged into a control it does not belong to.
- **The engine's own mapping is honored, not overwritten.** Ingest already
  attaches a per-finding ``control_mapping`` (OWASP / CWE / MITRE ids the engine
  emitted). OWASP ids resolve straight onto the OWASP framework; CWE and MITRE
  ids, which name no curated framework here, are carried through in
  ``engine_references`` so an engine-attested reference is never lost.

Computed on read (a pure function of ``deployment.findings.all()``), like
:func:`assurance.capability.assess_capabilities` and
:func:`assurance.boundary.assess_boundary` — no new record, no migration, no
timestamp in the payload. Prefetch ``findings`` on the caller side to keep it
query-light.

The return shape of :func:`build_compliance_map`::

    {
      "frameworks": [                     # one per curated framework, stable order
        {
          "key": "nist_800_53",
          "name": "NIST SP 800-53 Rev 5",
          "controls": [                   # only controls a finding TOUCHED, worst first
            {
              "control_id": "SI-10",
              "name": "Information Input Validation",
              "family": "SI",             # NIST only; None for the others
              "family_name": "System and Information Integrity",  # NIST only; None otherwise
              "catalogued": True,         # is this id in our curated catalog?
              "active_finding_count": 2,  # open findings against this control
              "resolved_finding_count": 1,  # historically touched, now resolved
              "worst_severity": "high",   # worst among ACTIVE findings; None if none active
              "finding_types": ["sql_injection", "xss"],  # sorted, distinct
            },
            ...
          ],
          "summary": {
            "controls_touched": 4,               # controls with >=1 finding (any status)
            "controls_with_active_findings": 3,  # open control gaps
            "worst_severity": "high",            # worst active in the framework; None if none
          },
        },
        ...  # owasp_2021, owasp_llm_2025, dod_zero_trust
      ],
      "unmapped": [                        # finding_types mapping to no framework control
        {
          "finding_type": "some_new_type",
          "active_finding_count": 1,
          "resolved_finding_count": 0,
          "worst_severity": "medium",      # worst among active; None if none active
        },
        ...
      ],
      "engine_references": [               # engine control_mapping ids outside the curated frameworks
        {
          "taxonomy": "cwe",
          "id": "CWE-89",
          "finding_count": 2,             # findings (any status) carrying this id
          "finding_types": ["sql_injection"],
        },
        ...  # e.g. MITRE ATT&CK technique ids
      ],
      "summary": {
        "total_findings": 7,
        "active_findings": 5,
        "resolved_findings": 2,
        "mapped_finding_types": 4,        # distinct types touching >=1 framework control
        "unmapped_finding_types": 1,
        "frameworks": 4,
        "controls_touched": 11,           # distinct controls touched across all frameworks
        "controls_with_active_findings": 9,
        "worst_severity": "critical",     # worst active across every touched control; None if none
      },
    }
"""

from __future__ import annotations

from .models import RESOLVED_FINDING_STATUSES, SEVERITY_ORDER, severity_rank

# Findings in these states are resolved — no longer an open control gap. Mirrors
# ``assurance.decision._RESOLVED_STATUSES`` so the two views agree on what
# "active" means. A resolved finding may still be listed against the control it
# historically touched, but with a zero active count and no worst severity.
# The one definition lives in ``assurance.models`` beside the statuses themselves.
# Seven modules each kept their own copy of this set, and every one of their
# comments said it "mirrors" the others so every view would agree on what "active"
# means -- which is precisely the arrangement that lets them stop agreeing. Adding
# a status meant editing eight places and silently disagreeing if you missed one.
_RESOLVED_STATUSES = RESOLVED_FINDING_STATUSES

# ---------------------------------------------------------------------------
# Framework keys and curated control catalogs (module data)
# ---------------------------------------------------------------------------

FRAMEWORK_NIST = "nist_800_53"
FRAMEWORK_OWASP = "owasp_2021"
FRAMEWORK_OWASP_LLM = "owasp_llm_2025"
FRAMEWORK_DOD_ZT = "dod_zero_trust"

# NIST SP 800-53 Rev 5 control families — the 18 the catalog is organised by. A
# curated control below carries its family so a reader sees the neighbourhood a
# finding lands in even when the specific control is not itemised.
_NIST_FAMILIES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "AT": "Awareness and Training",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

# The specific NIST controls most relevant to the web/AI findings Athena ingests.
# Curated, not exhaustive — Rev 5 titles (e.g. AU-2 is "Event Logging" in Rev 5,
# renamed from Rev 4's "Audit Events"). A control id outside this set that a
# finding still maps to is surfaced as un-catalogued rather than dropped.
_NIST_CONTROLS = {
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-6": "Least Privilege",
    "AU-2": "Event Logging",
    "AU-3": "Content of Audit Records",
    "CM-6": "Configuration Settings",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SC-5": "Denial-of-Service Protection",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-13": "Cryptographic Protection",
    "SC-23": "Session Authenticity",
    "SI-3": "Malicious Code Protection",
    "SI-10": "Information Input Validation",
    "SI-15": "Information Output Filtering",
}

# OWASP Top 10 2021. Ids match the engine's own ``control_mapping.owasp`` format
# ("A03:2021"), so an engine-attested OWASP id resolves straight onto this catalog.
_OWASP_CONTROLS = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

# OWASP Top 10 for LLM Applications, 2025.
_OWASP_LLM_CONTROLS = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# DoD Zero Trust — the seven pillars, treated as the framework's "controls".
_DOD_ZT_CONTROLS = {
    "user": "User",
    "device": "Device",
    "app_workload": "Applications & Workloads",
    "data": "Data",
    "network": "Network & Environment",
    "automation": "Automation & Orchestration",
    "visibility": "Visibility & Analytics",
}

# The curated frameworks, in the order they are reported. Each: (key, name,
# catalog id → name). NIST carries families separately (see ``_nist_family``).
_FRAMEWORKS = (
    (FRAMEWORK_NIST, "NIST SP 800-53 Rev 5", _NIST_CONTROLS),
    (FRAMEWORK_OWASP, "OWASP Top 10 2021", _OWASP_CONTROLS),
    (FRAMEWORK_OWASP_LLM, "OWASP Top 10 for LLM Applications 2025", _OWASP_LLM_CONTROLS),
    (FRAMEWORK_DOD_ZT, "DoD Zero Trust", _DOD_ZT_CONTROLS),
)
_FRAMEWORK_NAMES = {key: name for key, name, _ in _FRAMEWORKS}
_FRAMEWORK_CATALOGS = {key: catalog for key, _, catalog in _FRAMEWORKS}
# The stable index of a framework key, for sorting.
_FRAMEWORK_ORDER = {key: i for i, (key, _, _) in enumerate(_FRAMEWORKS)}


def _nist_family(control_id: str) -> tuple[str | None, str | None]:
    """(family code, family name) for a NIST control id ("SC-7" → ("SC", ...)),
    or (None, None) for a control whose family is not one we catalog."""
    code = control_id.split("-", 1)[0].strip().upper()
    name = _NIST_FAMILIES.get(code)
    return (code, name) if name else (None, None)


# ---------------------------------------------------------------------------
# finding_type → curated control ids, across the frameworks
# ---------------------------------------------------------------------------

# The curated crosswalk. Each finding_type maps to the control ids it lands on in
# each framework (a framework with no mapping for a type is simply omitted). This
# is the static layer; a finding's own engine ``control_mapping`` is merged on top
# per finding (see ``_engine_controls``), so an engine-attested OWASP id widens the
# coverage of the specific finding that carries it without editing this table.
_FINDING_TYPE_CONTROLS: dict[str, dict[str, tuple[str, ...]]] = {
    "sql_injection": {
        FRAMEWORK_NIST: ("SI-10", "RA-5"),
        FRAMEWORK_OWASP: ("A03:2021",),
        FRAMEWORK_DOD_ZT: ("data", "app_workload"),
    },
    "sqli": {
        FRAMEWORK_NIST: ("SI-10", "RA-5"),
        FRAMEWORK_OWASP: ("A03:2021",),
        FRAMEWORK_DOD_ZT: ("data", "app_workload"),
    },
    "xss": {
        FRAMEWORK_NIST: ("SI-10", "SI-15"),
        FRAMEWORK_OWASP: ("A03:2021",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "csrf": {
        FRAMEWORK_NIST: ("SC-23", "AC-3"),
        FRAMEWORK_OWASP: ("A01:2021",),
        FRAMEWORK_DOD_ZT: ("user", "app_workload"),
    },
    "cors_misconfiguration": {
        FRAMEWORK_NIST: ("AC-3", "AC-4", "SC-7"),
        FRAMEWORK_OWASP: ("A05:2021",),
        FRAMEWORK_DOD_ZT: ("network", "app_workload"),
    },
    "command_injection": {
        FRAMEWORK_NIST: ("SI-10", "SI-3", "RA-5"),
        FRAMEWORK_OWASP: ("A03:2021",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "directory_traversal": {
        FRAMEWORK_NIST: ("AC-3", "SI-10"),
        FRAMEWORK_OWASP: ("A01:2021",),
        FRAMEWORK_DOD_ZT: ("data", "app_workload"),
    },
    "header_injection": {
        FRAMEWORK_NIST: ("SI-10",),
        FRAMEWORK_OWASP: ("A03:2021",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "missing_security_header": {
        FRAMEWORK_NIST: ("CM-6", "SC-7"),
        FRAMEWORK_OWASP: ("A05:2021",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "misconfiguration": {
        FRAMEWORK_NIST: ("CM-6",),
        FRAMEWORK_OWASP: ("A05:2021",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "security_misconfiguration": {
        FRAMEWORK_NIST: ("CM-6",),
        FRAMEWORK_OWASP: ("A05:2021",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "insecure_cookie": {
        FRAMEWORK_NIST: ("SC-8", "SC-23"),
        FRAMEWORK_OWASP: ("A05:2021",),
        FRAMEWORK_DOD_ZT: ("user", "data"),
    },
    "ssl_error": {
        FRAMEWORK_NIST: ("SC-8", "SC-13"),
        FRAMEWORK_OWASP: ("A02:2021",),
        FRAMEWORK_DOD_ZT: ("network", "data"),
    },
    "auth_bruteforce": {
        FRAMEWORK_NIST: ("IA-2", "IA-5"),
        FRAMEWORK_OWASP: ("A07:2021",),
        FRAMEWORK_DOD_ZT: ("user",),
    },
    "endpoint_exposed": {
        FRAMEWORK_NIST: ("AC-3", "SC-7", "RA-5"),
        FRAMEWORK_OWASP: ("A01:2021",),
        FRAMEWORK_DOD_ZT: ("network", "app_workload", "visibility"),
    },
    "ssrf": {
        FRAMEWORK_NIST: ("SC-7", "AC-4"),
        FRAMEWORK_OWASP: ("A10:2021",),
        FRAMEWORK_DOD_ZT: ("network",),
    },
    "sensitive_data_exposure": {
        FRAMEWORK_NIST: ("SC-8", "SC-13"),
        FRAMEWORK_OWASP: ("A02:2021",),
        FRAMEWORK_OWASP_LLM: ("LLM02",),
        FRAMEWORK_DOD_ZT: ("data",),
    },
    "insecure_deserialization": {
        FRAMEWORK_NIST: ("SI-10",),
        FRAMEWORK_OWASP: ("A08:2021",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "vulnerable_component": {
        FRAMEWORK_NIST: ("RA-5",),
        FRAMEWORK_OWASP: ("A06:2021",),
        FRAMEWORK_OWASP_LLM: ("LLM03",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "outdated_component": {
        FRAMEWORK_NIST: ("RA-5",),
        FRAMEWORK_OWASP: ("A06:2021",),
        FRAMEWORK_OWASP_LLM: ("LLM03",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "missing_logging": {
        FRAMEWORK_NIST: ("AU-2", "AU-3"),
        FRAMEWORK_OWASP: ("A09:2021",),
        FRAMEWORK_DOD_ZT: ("visibility",),
    },
    # LLM / AI-native and capability/boundary-derived finding types.
    "prompt_injection": {
        FRAMEWORK_NIST: ("SI-10", "SI-15"),
        FRAMEWORK_OWASP: ("A03:2021",),
        FRAMEWORK_OWASP_LLM: ("LLM01",),
        FRAMEWORK_DOD_ZT: ("app_workload", "data"),
    },
    "sensitive_information_disclosure": {
        FRAMEWORK_NIST: ("SC-8", "AC-3"),
        FRAMEWORK_OWASP_LLM: ("LLM02",),
        FRAMEWORK_DOD_ZT: ("data",),
    },
    "insecure_output_handling": {
        FRAMEWORK_NIST: ("SI-15",),
        FRAMEWORK_OWASP_LLM: ("LLM05",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "excessive_agency": {
        FRAMEWORK_NIST: ("AC-6", "AC-3"),
        FRAMEWORK_OWASP_LLM: ("LLM06",),
        FRAMEWORK_DOD_ZT: ("automation", "app_workload"),
    },
    "excessive_permission": {
        FRAMEWORK_NIST: ("AC-6",),
        FRAMEWORK_OWASP_LLM: ("LLM06",),
        FRAMEWORK_DOD_ZT: ("automation", "user"),
    },
    "system_prompt_leakage": {
        FRAMEWORK_NIST: ("AC-3",),
        FRAMEWORK_OWASP_LLM: ("LLM07",),
        FRAMEWORK_DOD_ZT: ("data",),
    },
    "data_poisoning": {
        FRAMEWORK_NIST: ("SI-3", "SI-10"),
        FRAMEWORK_OWASP_LLM: ("LLM04",),
        FRAMEWORK_DOD_ZT: ("data",),
    },
    "model_poisoning": {
        FRAMEWORK_NIST: ("SI-3",),
        FRAMEWORK_OWASP_LLM: ("LLM04",),
        FRAMEWORK_DOD_ZT: ("data",),
    },
    "vector_weakness": {
        FRAMEWORK_OWASP_LLM: ("LLM08",),
        FRAMEWORK_DOD_ZT: ("data",),
    },
    "misinformation": {
        FRAMEWORK_OWASP_LLM: ("LLM09",),
        FRAMEWORK_DOD_ZT: ("data",),
    },
    "unbounded_consumption": {
        FRAMEWORK_NIST: ("SC-5",),
        FRAMEWORK_OWASP_LLM: ("LLM10",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    "supply_chain": {
        FRAMEWORK_NIST: ("RA-5",),
        FRAMEWORK_OWASP: ("A06:2021",),
        FRAMEWORK_OWASP_LLM: ("LLM03",),
        FRAMEWORK_DOD_ZT: ("app_workload",),
    },
    # Boundary/capability-derived: a shadow (unmanaged) data destination or an
    # excess capability the boundary/capability assessments surface as findings.
    "shadow_component": {
        FRAMEWORK_NIST: ("CM-6", "AC-4"),
        FRAMEWORK_OWASP: ("A05:2021",),
        FRAMEWORK_OWASP_LLM: ("LLM03",),
        FRAMEWORK_DOD_ZT: ("visibility", "network"),
    },
    "data_boundary_violation": {
        FRAMEWORK_NIST: ("AC-4", "SC-7"),
        FRAMEWORK_DOD_ZT: ("data", "network"),
    },
}

# The taxonomy keys of a per-finding ``control_mapping`` that resolve straight onto
# a curated framework. OWASP ids ("A03:2021") ARE OWASP Top 10 control ids; CWE and
# MITRE name no curated framework here, so their ids are surfaced as engine
# references rather than forced onto a control they do not belong to.
_ENGINE_KEY_FRAMEWORK = {
    "owasp": FRAMEWORK_OWASP,
}


# ---------------------------------------------------------------------------
# Per-finding mapping
# ---------------------------------------------------------------------------


def _static_controls(finding_type: str) -> dict[str, tuple[str, ...]]:
    """The curated {framework: (control ids,)} for a finding type. Case- and
    whitespace-insensitive on the type. Empty when the type is not in the
    crosswalk — the caller then treats it as unmapped."""
    return _FINDING_TYPE_CONTROLS.get((finding_type or "").strip().lower(), {})


def _engine_controls(control_mapping) -> tuple[dict[str, list[str]], list[tuple[str, str]]]:
    """Split a finding's engine ``control_mapping`` into (framework controls we can
    resolve, engine references we cannot). The first is {framework: [ids]} for
    taxonomies that name a curated framework (OWASP); the second is a list of
    (taxonomy, id) for the rest (CWE, MITRE), carried through untouched so an
    engine-attested reference is never lost."""
    resolved: dict[str, list[str]] = {}
    references: list[tuple[str, str]] = []
    if not isinstance(control_mapping, dict):
        return resolved, references
    for taxonomy, ids in control_mapping.items():
        key = str(taxonomy).strip().lower()
        values = ids if isinstance(ids, (list, tuple)) else [ids]
        for raw in values:
            control_id = str(raw).strip()
            if not control_id:
                continue
            framework = _ENGINE_KEY_FRAMEWORK.get(key)
            if framework:
                resolved.setdefault(framework, []).append(control_id)
            else:
                references.append((key, control_id))
    return resolved, references


def _merged_controls(finding) -> dict[str, list[str]]:
    """Every (framework → control ids) a finding lands on: the curated crosswalk for
    its type, widened by the OWASP ids the engine attached to this finding. Ids are
    de-duplicated per framework, order preserved (static ids first)."""
    merged: dict[str, list[str]] = {}
    for framework, ids in _static_controls(finding.finding_type).items():
        merged.setdefault(framework, []).extend(ids)
    engine_resolved, _ = _engine_controls(finding.control_mapping)
    for framework, ids in engine_resolved.items():
        merged.setdefault(framework, []).extend(ids)
    return {fw: list(dict.fromkeys(ids)) for fw, ids in merged.items() if ids}


# ---------------------------------------------------------------------------
# Accumulators
# ---------------------------------------------------------------------------


class _Control:
    """One control a finding touched, accumulating the findings that land on it.
    'Touched' is evidence of a gap, never that the control passes."""

    def __init__(self, framework: str, control_id: str):
        self.framework = framework
        self.control_id = control_id
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
        # Worst severity among ACTIVE findings only — a resolved-only control is
        # not an open gap, so it has no worst severity.
        return SEVERITY_ORDER[self._worst_active_rank] if self._worst_active_rank >= 0 else None

    def to_dict(self) -> dict:
        catalog = _FRAMEWORK_CATALOGS[self.framework]
        family, family_name = (
            _nist_family(self.control_id) if self.framework == FRAMEWORK_NIST else (None, None)
        )
        return {
            "control_id": self.control_id,
            "name": catalog.get(self.control_id),
            "family": family,
            "family_name": family_name,
            # Un-catalogued: an id a finding mapped to that is not in our curated
            # catalog (e.g. an engine OWASP id we do not itemise). Surfaced, not
            # dropped, and honest that we hold no name for it.
            "catalogued": self.control_id in catalog,
            "active_finding_count": self.active,
            "resolved_finding_count": self.resolved,
            "worst_severity": self.worst_severity,
            "finding_types": sorted(self.finding_types),
        }


class _Unmapped:
    """A finding_type that touched no curated framework control — a gap in the map
    itself, surfaced rather than dropped."""

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


def build_compliance_map(deployment) -> dict:
    """The full compliance map for a deployment: where its findings land against
    each curated control framework, which finding types map nowhere, and the
    engine references outside the curated frameworks. Prefetch ``findings`` on the
    caller side. Pure and side-effect-free, deterministic, no timestamp.

    Evidence of gaps, not a certificate — a *touched* control is one with an open
    finding against it, the opposite of a passing control. See the module
    docstring for the full return shape."""
    # framework key → {control id → _Control}
    controls: dict[str, dict[str, _Control]] = {key: {} for key, _, _ in _FRAMEWORKS}
    unmapped: dict[str, _Unmapped] = {}
    # (taxonomy, id) → {"count": int, "types": set[str]}
    engine_refs: dict[tuple[str, str], dict] = {}

    total = active_total = resolved_total = 0
    mapped_types: set[str] = set()

    for finding in deployment.findings.all():
        total += 1
        is_active = finding.status not in _RESOLVED_STATUSES
        if is_active:
            active_total += 1
        else:
            resolved_total += 1
        ftype = (finding.finding_type or "").strip()

        merged = _merged_controls(finding)
        if merged:
            mapped_types.add(ftype)
            for framework, ids in merged.items():
                bucket = controls[framework]
                for control_id in ids:
                    control = bucket.get(control_id)
                    if control is None:
                        control = _Control(framework, control_id)
                        bucket[control_id] = control
                    control.add(active=is_active, severity=finding.severity, finding_type=ftype)
        else:
            # No framework control — surfaced honestly as an unmapped type, keyed
            # by the type so many findings of one type roll up to one entry.
            key = ftype or "(unspecified)"
            entry = unmapped.get(key)
            if entry is None:
                entry = _Unmapped(key)
                unmapped[key] = entry
            entry.add(active=is_active, severity=finding.severity)

        # Engine references outside the curated frameworks (CWE, MITRE) — carried
        # through for every finding, mapped or not, so nothing the engine attested
        # is lost.
        _, references = _engine_controls(finding.control_mapping)
        for taxonomy, control_id in references:
            ref = engine_refs.get((taxonomy, control_id))
            if ref is None:
                ref = {"count": 0, "types": set()}
                engine_refs[(taxonomy, control_id)] = ref
            ref["count"] += 1
            if ftype:
                ref["types"].add(ftype)

    frameworks = [_framework_dict(key, controls[key]) for key, _, _ in _FRAMEWORKS]

    unmapped_list = [u.to_dict() for u in unmapped.values()]
    # Worst active first, then most active, then type name — a stable order.
    unmapped_list.sort(
        key=lambda u: (
            -severity_rank(u["worst_severity"]) if u["worst_severity"] else 1,
            -u["active_finding_count"],
            u["finding_type"],
        )
    )

    engine_reference_list = [
        {
            "taxonomy": taxonomy,
            "id": control_id,
            "finding_count": ref["count"],
            "finding_types": sorted(ref["types"]),
        }
        for (taxonomy, control_id), ref in engine_refs.items()
    ]
    engine_reference_list.sort(key=lambda r: (r["taxonomy"], r["id"]))

    overall_worst = None
    controls_touched = controls_with_active = 0
    for framework in frameworks:
        controls_touched += framework["summary"]["controls_touched"]
        controls_with_active += framework["summary"]["controls_with_active_findings"]
        overall_worst = _worst(overall_worst, framework["summary"]["worst_severity"])

    summary = {
        "total_findings": total,
        "active_findings": active_total,
        "resolved_findings": resolved_total,
        "mapped_finding_types": len(mapped_types),
        "unmapped_finding_types": len(unmapped_list),
        "frameworks": len(_FRAMEWORKS),
        "controls_touched": controls_touched,
        "controls_with_active_findings": controls_with_active,
        "worst_severity": overall_worst,
    }
    return {
        "frameworks": frameworks,
        "unmapped": unmapped_list,
        "engine_references": engine_reference_list,
        "summary": summary,
    }


def _framework_dict(key: str, by_id: dict[str, _Control]) -> dict:
    """Render one framework: the controls a finding touched (worst active first),
    and an honest per-framework roll-up. A framework nothing touched renders with an
    empty control list and a zeroed summary — an empty map, not a passing one."""
    control_list = [c.to_dict() for c in by_id.values()]
    # Worst active severity first, then most open findings, then id — deterministic.
    control_list.sort(
        key=lambda c: (
            -severity_rank(c["worst_severity"]) if c["worst_severity"] else 1,
            -c["active_finding_count"],
            c["control_id"],
        )
    )
    worst = None
    with_active = 0
    for control in control_list:
        if control["active_finding_count"] > 0:
            with_active += 1
            worst = _worst(worst, control["worst_severity"])
    return {
        "key": key,
        "name": _FRAMEWORK_NAMES[key],
        "controls": control_list,
        "summary": {
            "controls_touched": len(control_list),
            "controls_with_active_findings": with_active,
            "worst_severity": worst,
        },
    }
