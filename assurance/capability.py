"""AI System Capability Map — ground truth of what a deployment can *do* (Phase 1.3).

The prerequisite for the data-boundary (1.4) and access assessments: before you
can judge whether a system's data flows or permissions are within an approved
boundary, you need the honest inventory of the *powers* the system actually has.
This module builds that inventory from signals that already exist — nothing it
must invent:

- **The asset graph** (Phase 1.1/1.2/1.6). Each component a deployment is built
  from grants a capability: a model can generate, an agent can act autonomously,
  a tool or MCP server can reach outside the model, a vector DB can retrieve, an
  API is a network surface. The asset kind is the capability; the asset is its
  evidence.
- **The declared tool permission map** (the ``permissions`` a tool/MCP asset
  carries, from ``target_config.tools[]``). A tool that declares it can execute
  code, reach the network, touch the filesystem, send mail or move money is a
  materially higher-risk *capability*, surfaced on its own — the OWASP-agentic
  concerns (tool abuse, privilege escalation) named as powers, not buried in a
  metadata blob.

It is honest in the same way the boundary assessment is:

- A capability evidenced only by **unmanaged** (shadow) components is a **shadow
  capability** — a power the system has that no managed, declared component
  accounts for. It is surfaced, and its risk is raised one band, never hidden.
- A capability is marked **declared** when a declared/managed component grants
  it, and its **risk** is the highest among its sources. Nothing here observes
  the network or executes the target; it reconciles what discovery recorded into
  the vocabulary of capability. A mechanical mapping, honest about its inputs.

Computed on read (a pure function of the stored asset graph), like
:func:`assurance.boundary.assess_boundary` — no new record, no migration.
Prefetch ``assets`` on the caller side to keep it query-light.
"""

from __future__ import annotations

from .models import Asset

# Risk bands, strongest concern first. A capability's risk is the highest band
# among the components that grant it, raised one step when it is a shadow one.
RISK_HIGH = "high"
RISK_ELEVATED = "elevated"
RISK_BASELINE = "baseline"
_RISK_ORDER = (RISK_HIGH, RISK_ELEVATED, RISK_BASELINE)  # index 0 = most concerning
_RISK_RAISED = {RISK_BASELINE: RISK_ELEVATED, RISK_ELEVATED: RISK_HIGH, RISK_HIGH: RISK_HIGH}


def _max_risk(a: str, b: str) -> str:
    return a if _RISK_ORDER.index(a) <= _RISK_ORDER.index(b) else b


# The classifications that make an asset *managed* — a governed component we can
# tie a capability to. Anything else (unmanaged / unknown / high_risk) is a
# shadow source: the power is present, but no approved component accounts for it.
_MANAGED = {Asset.Classification.APPROVED, Asset.Classification.KNOWN}

# One capability per asset kind: the power that owning that component confers.
# The label is what the system can *do*, not what the component *is*.
_KIND_CAPABILITY = {
    Asset.Kind.MODEL: {
        "key": "model_inference",
        "label": "Generate model output",
        "category": "cognition",
        "description": "Produces text or predictions from a language model.",
        "risk": RISK_BASELINE,
    },
    Asset.Kind.AGENT: {
        "key": "autonomous_action",
        "label": "Act autonomously",
        "category": "agency",
        "description": "Runs an agentic loop that can chain steps and invoke tools "
        "without per-step human approval.",
        "risk": RISK_ELEVATED,
    },
    Asset.Kind.TOOL: {
        "key": "tool_invocation",
        "label": "Invoke tools",
        "category": "integration",
        "description": "Calls a tool or function that acts outside the model.",
        "risk": RISK_ELEVATED,
    },
    Asset.Kind.MCP_SERVER: {
        "key": "external_tool_access",
        "label": "Reach an external MCP server",
        "category": "integration",
        "description": "Connects to an MCP server for tools and data outside the deployment.",
        "risk": RISK_ELEVATED,
    },
    Asset.Kind.SKILL: {
        "key": "skill_execution",
        "label": "Run agent skills",
        "category": "integration",
        "description": "Executes a packaged agent skill.",
        "risk": RISK_ELEVATED,
    },
    Asset.Kind.VECTOR_DB: {
        "key": "retrieval",
        "label": "Retrieve from a knowledge store",
        "category": "data",
        "description": "Reads context from a vector database (retrieval-augmented generation).",
        "risk": RISK_BASELINE,
    },
    Asset.Kind.DATA_STORE: {
        "key": "data_persistence",
        "label": "Read and write a data store",
        "category": "data",
        "description": "Persists or reads data in a backing store.",
        "risk": RISK_ELEVATED,
    },
    Asset.Kind.API: {
        "key": "network_surface",
        "label": "Expose or reach an HTTP surface",
        "category": "network",
        "description": "Serves or calls an HTTP endpoint.",
        "risk": RISK_BASELINE,
    },
    Asset.Kind.GATEWAY: {
        "key": "model_routing",
        "label": "Route through an AI gateway",
        "category": "network",
        "description": "Sends traffic through an AI gateway that can reach multiple models.",
        "risk": RISK_BASELINE,
    },
    Asset.Kind.SERVICE_ACCOUNT: {
        "key": "identity_delegation",
        "label": "Act under a service identity",
        "category": "identity",
        "description": "Holds a machine identity the system can act as.",
        "risk": RISK_ELEVATED,
    },
}

# Sensitive capabilities read out of a tool/MCP asset's declared permission map.
# Each entry: (keyword matchers, capability spec). Matching is substring and
# case-insensitive on each declared permission string, so "fs:read",
# "filesystem", "read_file" all resolve to filesystem access. Conservative and
# additive — a permission that matches nothing is still surfaced verbatim as an
# "other" declared permission rather than dropped.
_PERMISSION_CAPABILITIES = [
    (
        ("exec", "shell", "subprocess", "command", "code_interpreter", "run_code", "eval"),
        {
            "key": "code_execution",
            "label": "Execute code or shell commands",
            "category": "execution",
            "description": "A tool declares it can run code or shell commands.",
            "risk": RISK_HIGH,
        },
    ),
    (
        ("delete", "destroy", "drop", "remove", "wipe", "truncate"),
        {
            "key": "destructive_action",
            "label": "Perform destructive actions",
            "category": "execution",
            "description": "A tool declares it can delete or destroy data or resources.",
            "risk": RISK_HIGH,
        },
    ),
    (
        ("payment", "charge", "transfer", "purchase", "order", "invoice", "refund", "wire"),
        {
            "key": "financial_action",
            "label": "Move money",
            "category": "financial",
            "description": "A tool declares it can initiate a financial transaction.",
            "risk": RISK_HIGH,
        },
    ),
    (
        ("admin", "sudo", "root", "escalat", "grant", "iam", "privilege"),
        {
            "key": "privileged_control",
            "label": "Exercise privileged control",
            "category": "identity",
            "description": "A tool declares administrative or privilege-granting authority.",
            "risk": RISK_HIGH,
        },
    ),
    (
        ("network", "http", "url", "fetch", "web", "browse", "internet", "request", "egress"),
        {
            "key": "network_access",
            "label": "Make outbound network calls",
            "category": "network",
            "description": "A tool declares it can reach the network or the open web.",
            "risk": RISK_ELEVATED,
        },
    ),
    (
        ("file", "filesystem", "fs:", "disk", "path", "read_file", "write_file"),
        {
            "key": "filesystem_access",
            "label": "Read or write the filesystem",
            "category": "data",
            "description": "A tool declares it can access the filesystem.",
            "risk": RISK_ELEVATED,
        },
    ),
    (
        ("email", "smtp", "mail", "slack", "sms", "notify", "send_message", "message"),
        {
            "key": "messaging",
            "label": "Send messages or email",
            "category": "communication",
            "description": "A tool declares it can send email or messages on the system's behalf.",
            "risk": RISK_ELEVATED,
        },
    ),
    (
        ("db", "sql", "database", "datastore", "query", "table", "collection"),
        {
            "key": "data_query",
            "label": "Query a database",
            "category": "data",
            "description": "A tool declares it can query a database or data store.",
            "risk": RISK_ELEVATED,
        },
    ),
]


def _source(asset: Asset, detail: str = "") -> dict:
    """One evidence row: the component that grants a capability, and how."""
    return {
        "asset_name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        "managed": asset.classification in _MANAGED,
        "detail": detail,
    }


class _Capability:
    """A power the system has, accumulating the components that evidence it."""

    def __init__(self, spec: dict):
        self.key = spec["key"]
        self.label = spec["label"]
        self.category = spec["category"]
        self.description = spec["description"]
        self.base_risk = spec["risk"]
        self.sources: list[dict] = []

    def add(self, source: dict) -> None:
        self.sources.append(source)

    def to_dict(self) -> dict:
        managed = any(s["managed"] for s in self.sources)
        # Risk = the highest base risk among sources; a shadow capability (no
        # managed component accounts for it) is raised one band.
        risk = self.base_risk
        if not managed:
            risk = _RISK_RAISED[risk]
        return {
            "key": self.key,
            "label": self.label,
            "category": self.category,
            "description": self.description,
            "risk": risk,
            # Declared: a managed/declared component grants this power.
            "declared": managed,
            # Shadow: only unmanaged components grant it — a power nobody approved.
            "shadow": not managed,
            "sources": sorted(self.sources, key=lambda s: (s["managed"], s["asset_name"])),
        }


def _permission_specs(permission: str) -> list[dict]:
    """Every sensitive-capability spec a declared permission string matches. A
    permission can carry more than one power (``"exec+network"``)."""
    p = permission.lower()
    return [spec for matchers, spec in _PERMISSION_CAPABILITIES if any(m in p for m in matchers)]


def assess_capabilities(deployment) -> dict:
    """The full capability map for a deployment: every power it can exercise, the
    components that evidence each, and an honest roll-up. Prefetch ``assets`` on
    the caller side. Pure and side-effect-free."""
    by_key: dict[str, _Capability] = {}

    def ensure(spec: dict) -> _Capability:
        cap = by_key.get(spec["key"])
        if cap is None:
            cap = _Capability(spec)
            by_key[spec["key"]] = cap
        return cap

    for asset in deployment.assets.all():
        # The capability the component's kind confers.
        spec = _KIND_CAPABILITY.get(asset.kind)
        if spec is not None:
            ensure(spec).add(_source(asset))

        # Sensitive capabilities from the tool's declared permission map.
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        permissions = metadata.get("permissions")
        if isinstance(permissions, list):
            for raw in permissions:
                perm = str(raw).strip()
                if not perm:
                    continue
                for pspec in _permission_specs(perm):
                    ensure(pspec).add(_source(asset, detail=f"permission '{perm}'"))

    capabilities = [cap.to_dict() for cap in by_key.values()]
    # Most concerning first: by risk band, shadow before managed within a band,
    # then label for a stable order.
    capabilities.sort(
        key=lambda c: (_RISK_ORDER.index(c["risk"]), not c["shadow"], c["label"])
    )

    # A category roll-up: the reader's map of *kinds* of power and the worst risk
    # in each, in a stable most-concerning-first order.
    categories: dict[str, dict] = {}
    for cap in capabilities:
        entry = categories.setdefault(cap["category"], {"category": cap["category"], "count": 0, "max_risk": RISK_BASELINE})
        entry["count"] += 1
        entry["max_risk"] = _max_risk(entry["max_risk"], cap["risk"])
    category_list = sorted(
        categories.values(), key=lambda e: (_RISK_ORDER.index(e["max_risk"]), e["category"])
    )

    summary = {
        "total": len(capabilities),
        "high_risk": sum(1 for c in capabilities if c["risk"] == RISK_HIGH),
        "elevated": sum(1 for c in capabilities if c["risk"] == RISK_ELEVATED),
        "baseline": sum(1 for c in capabilities if c["risk"] == RISK_BASELINE),
        "declared": sum(1 for c in capabilities if c["declared"]),
        "shadow": sum(1 for c in capabilities if c["shadow"]),
    }
    return {
        "capabilities": capabilities,
        "categories": category_list,
        "summary": summary,
    }
