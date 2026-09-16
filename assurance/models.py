"""The Athena assurance data model — the system of record.

Phase 0.1 of the reconciled Athena roadmap. Before this, a finding existed only
as an untyped dict inside ``PentestScan.engine_response`` (raw engine JSON), and
structured findings lived separately in the dashboard's own store. There was no
shared ``Finding`` / ``Evidence`` / ``Provider`` / ``Deployment`` / ``Asset``
model, so every assurance feature had to be built twice and the "Assurance Graph"
had nothing coherent to sit on.

These models make the Django control-plane the single source of truth: a
completed scan's engine response is ingested (see ``assurance.ingest``) into
structured, queryable rows that carry the full finding schema the product needs
— impact, ownership, lifecycle status, retest flag, control mapping — and every
conclusion is graded by *how strongly it is known* via the evidence
classification taxonomy. Django still does not execute scans; the CyberEngine
remains the thing that scans. This is where its output becomes durable assurance.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

# ---------------------------------------------------------------------------
# Shared vocabularies
# ---------------------------------------------------------------------------

# Cyber-physical / exposure severity, weakest to strongest. Matches the taxonomy
# the engine and the PentestScan verdict use, so a badge, a PDF, and a Finding
# row never disagree about how severe something is.
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
SEVERITY_CHOICES = (
    (SEVERITY_INFO, "Info"),
    (SEVERITY_LOW, "Low"),
    (SEVERITY_MEDIUM, "Medium"),
    (SEVERITY_HIGH, "High"),
    (SEVERITY_CRITICAL, "Critical"),
)
SEVERITY_ORDER = (SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index((severity or "").strip().lower())
    except ValueError:
        return 0


class EvidenceClass(models.TextChoices):
    """How strongly a conclusion is actually known — the discipline that keeps
    Mythos from turning assumptions into facts. Ordered strongest to weakest;
    ``strength()`` gives the ordinal so a caller can take the *weakest* evidence
    behind a finding as its honest confidence floor."""

    TECHNICALLY_VERIFIED = "technically_verified", "Technically verified"
    CONFIGURATION_VERIFIED = "configuration_verified", "Configuration verified"
    DOCUMENT_SUPPORTED = "document_supported", "Document supported"
    CONTRACTUALLY_STATED = "contractually_stated", "Contractually stated"
    VENDOR_ASSERTED = "vendor_asserted", "Vendor asserted"
    PARTIALLY_VERIFIED = "partially_verified", "Partially verified"
    UNKNOWN = "unknown", "Unknown"
    NOT_DOCUMENTED = "not_documented", "Not documented"


# Strongest → weakest. Index = strength ordinal (0 is strongest).
EVIDENCE_STRENGTH_ORDER = (
    EvidenceClass.TECHNICALLY_VERIFIED,
    EvidenceClass.CONFIGURATION_VERIFIED,
    EvidenceClass.DOCUMENT_SUPPORTED,
    EvidenceClass.CONTRACTUALLY_STATED,
    EvidenceClass.VENDOR_ASSERTED,
    EvidenceClass.PARTIALLY_VERIFIED,
    EvidenceClass.UNKNOWN,
    EvidenceClass.NOT_DOCUMENTED,
)


def evidence_strength(classification: str) -> int:
    """Ordinal for an evidence class (0 = strongest). Unknown values sort weakest
    so an unrecognised label never reads as strong evidence."""
    try:
        return EVIDENCE_STRENGTH_ORDER.index(EvidenceClass(classification))
    except (ValueError, KeyError):
        return len(EVIDENCE_STRENGTH_ORDER)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class Provider(models.Model):
    """A third-party AI or infrastructure provider a deployment relies on.

    Phase 0 keeps this minimal — an identity plus the provider-declared facts we
    can already record. Phase 1.5 (Provider Assurance Profile) grows it into a
    structured per-provider profile (region / retention / logging / training) with
    an evidence class on each field. What matters now is that a provider is a real
    row an Asset can point at, not a string repeated across findings."""

    class Kind(models.TextChoices):
        MODEL_PROVIDER = "model_provider", "Model provider"
        GATEWAY = "gateway", "AI gateway"
        EMBEDDING = "embedding", "Embedding provider"
        VECTOR_DB = "vector_db", "Vector database"
        OBSERVABILITY = "observability", "Observability / logging"
        CLOUD = "cloud", "Cloud"
        OTHER = "other", "Other"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    name = models.CharField(max_length=200)
    kind = models.CharField(max_length=32, choices=Kind.choices, default=Kind.OTHER)
    # Provider-declared facts (what they say; not yet independently measured).
    region = models.CharField(max_length=120, blank=True)
    notes = models.TextField(blank=True)
    # How strongly what we hold about this provider is known.
    evidence_class = models.CharField(
        max_length=32, choices=EvidenceClass.choices, default=EvidenceClass.VENDOR_ASSERTED
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["name", "kind"], name="uq_provider_name_kind"),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.get_kind_display()})"


# ---------------------------------------------------------------------------
# ProviderAssertion — a graded fact in a provider's assurance profile
# ---------------------------------------------------------------------------


class ProviderAssertion(models.Model):
    """One graded fact about a provider's assurance posture — the Provider
    Assurance Profile (Phase 1.5).

    A provider's posture is **declared, not measured**: nothing scans a vendor's
    data handling, so each fact (where it processes data, how long it retains it,
    what it logs, whether it trains on customer data) is a *claim* until evidence
    backs it. Every assertion therefore carries its own
    :class:`EvidenceClass` — ``vendor_asserted`` by default (they told us),
    upgraded to ``document_supported`` or ``contractually_stated`` when a report
    or DPA is on file. This is the evidence taxonomy applied *per field*, so a
    profile never reads as fact what is only a claim, and the weakest link is
    visible rather than averaged away."""

    class Field(models.TextChoices):
        REGION = "region", "Data region"
        DATA_RETENTION = "data_retention", "Data retention"
        LOGGING = "logging", "Logging"
        TRAINS_ON_DATA = "trains_on_data", "Trains on customer data"
        SUBPROCESSORS = "subprocessors", "Subprocessors"
        CERTIFICATIONS = "certifications", "Certifications"
        DPA = "dpa", "Data-processing agreement"

    class Source(models.TextChoices):
        VENDOR_DOC = "vendor_doc", "Vendor documentation"
        CONTRACT = "contract", "Contract / DPA"
        SELF_DECLARED = "self_declared", "Self-declared"
        MEASURED = "measured", "Independently measured"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    provider = models.ForeignKey(
        Provider, on_delete=models.CASCADE, related_name="assertions"
    )
    field = models.CharField(max_length=32, choices=Field.choices)
    # The asserted value, in the vendor's own words: "us-east-1", "30 days",
    # "No — zero-retention endpoint", "SOC 2 Type II".
    value = models.TextField(blank=True)
    # How strongly this particular fact is known. Defaults to a vendor assertion.
    evidence_class = models.CharField(
        max_length=32, choices=EvidenceClass.choices, default=EvidenceClass.VENDOR_ASSERTED
    )
    source = models.CharField(
        max_length=32, choices=Source.choices, default=Source.SELF_DECLARED, blank=True
    )
    notes = models.TextField(blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="provider_assertions",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["provider", "field"]
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "field"], name="uq_provider_assertion_provider_field"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.provider.name}: {self.get_field_display()} = {self.value[:40]}"


# ---------------------------------------------------------------------------
# Deployment — the AI system under assurance (the sellable unit)
# ---------------------------------------------------------------------------


class Deployment(models.Model):
    """One AI system under assurance — the unit a customer contract expands on
    ("AI systems under assurance", not scan counts).

    A deployment gathers the findings, evidence, assets, and the single
    deployment decision for one system in one environment. It is the anchor the
    Assurance Graph will hang nodes off, and the row the dashboard's Deployments
    page reads."""

    class Environment(models.TextChoices):
        DEV = "dev", "Development"
        STAGING = "staging", "Staging"
        PRODUCTION = "production", "Production"
        OTHER = "other", "Other"

    # The six-state deployment decision (Mythos shared vocabulary). Distinct from
    # a scan's status; this is the standing recommendation for the whole system,
    # completing the four PentestScan verdicts with the two the roadmap adds.
    class Decision(models.TextChoices):
        READY = "ready", "Ready"
        READY_RESTRICTED = "ready_restricted", "Ready with restrictions"
        NEEDS_MORE_EVIDENCE = "needs_more_evidence", "Requires additional evidence"
        NEEDS_REMEDIATION = "needs_remediation", "Requires remediation"
        NOT_RECOMMENDED = "not_recommended", "Not recommended"
        PAUSED = "paused", "Deployment paused"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    name = models.CharField(max_length=255)
    environment = models.CharField(
        max_length=32, choices=Environment.choices, default=Environment.PRODUCTION
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_deployments",
    )
    # The authorisation this system is assessed under, when one applies. Reuses
    # the existing engagement/scope model rather than inventing a second one.
    engagement = models.ForeignKey(
        "pentest.Engagement",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="deployments",
    )
    description = models.TextField(blank=True)
    # The current standing decision. Nullable: a deployment with no assessment yet
    # has no decision, and an absent decision is never READY.
    decision = models.CharField(
        max_length=32, choices=Decision.choices, null=True, blank=True, db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        indexes = [models.Index(fields=["environment"])]

    def __str__(self) -> str:
        return f"{self.name} [{self.get_environment_display()}]"


# ---------------------------------------------------------------------------
# Asset — a component of a deployment (Assurance Graph node precursor)
# ---------------------------------------------------------------------------


class Asset(models.Model):
    """One component of a deployment: a model, agent, tool, API, gateway, vector
    DB, service account, data store, MCP server, and so on.

    Phase 0 records assets as first-class rows so findings can attach to *what*
    they concern. Phase 1.1 (AI Asset Discovery) populates and classifies them;
    the ``classification`` field is here now so discovery has somewhere to write."""

    class Kind(models.TextChoices):
        MODEL = "model", "Model"
        AGENT = "agent", "Agent"
        TOOL = "tool", "Tool"
        API = "api", "API"
        GATEWAY = "gateway", "AI gateway"
        VECTOR_DB = "vector_db", "Vector database"
        SERVICE_ACCOUNT = "service_account", "Service account"
        DATA_STORE = "data_store", "Data store"
        MCP_SERVER = "mcp_server", "MCP server"
        OTHER = "other", "Other"

    class Classification(models.TextChoices):
        APPROVED = "approved", "Approved"
        KNOWN = "known", "Known"
        UNMANAGED = "unmanaged", "Unmanaged"
        UNKNOWN = "unknown", "Unknown"
        HIGH_RISK = "high_risk", "High risk"
        RETIRED = "retired", "Retired but reachable"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="assets"
    )
    kind = models.CharField(max_length=32, choices=Kind.choices, default=Kind.OTHER)
    name = models.CharField(max_length=255)
    # A stable identifier for the component: an endpoint URL, ARN, tool name, etc.
    identifier = models.CharField(max_length=1024, blank=True)
    provider = models.ForeignKey(
        Provider, on_delete=models.SET_NULL, null=True, blank=True, related_name="assets"
    )
    classification = models.CharField(
        max_length=32, choices=Classification.choices, default=Classification.KNOWN
    )
    metadata = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["deployment", "kind", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "kind", "identifier"],
                name="uq_asset_deployment_kind_identifier",
            ),
        ]
        indexes = [models.Index(fields=["deployment", "kind"])]

    def __str__(self) -> str:
        return f"{self.name} ({self.get_kind_display()})"


# ---------------------------------------------------------------------------
# Finding — the core assurance record
# ---------------------------------------------------------------------------


class Finding(models.Model):
    """One structured finding: what a scan concluded, reduced to the full schema
    a release decision and a remediation workflow need.

    The raw engine dict is preserved in ``raw`` for provenance, but the columns
    here are what the product queries on: severity, confidence, CVSS, **lifecycle
    status**, **owner**, **impact**, control mapping, and the **retest flag** —
    the fields the old ``engine_response`` JSON did not expose. A finding is
    deduplicated within a deployment by ``fingerprint`` so re-scanning updates a
    finding rather than duplicating it (the basis for change intelligence and
    retest tracking)."""

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        TRIAGED = "triaged", "Triaged"
        REMEDIATING = "remediating", "Remediating"
        RETESTING = "retesting", "Retesting"
        CLOSED = "closed", "Verified closed"
        ACCEPTED = "accepted", "Accepted risk"
        FALSE_POSITIVE = "false_positive", "False positive"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)

    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="findings"
    )
    asset = models.ForeignKey(
        Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="findings"
    )
    # The scan this finding was (last) observed in. SET_NULL so history-trimming a
    # scan never deletes the durable finding.
    scan = models.ForeignKey(
        "pentest.PentestScan",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assurance_findings",
    )

    # Stable dedup key within a deployment: hash of deployment + type + location.
    fingerprint = models.CharField(max_length=64, db_index=True)

    finding_type = models.CharField(max_length=128)
    title = models.CharField(max_length=512)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_INFO)
    confidence = models.FloatField(default=0.5)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=128, blank=True)

    status = models.CharField(
        max_length=24, choices=Status.choices, default=Status.OPEN, db_index=True
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_findings",
    )

    # Technical consequence, business consequence, and the fix — the narrative a
    # decision needs and the JSON did not carry as fields.
    impact = models.TextField(blank=True)
    business_impact = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    # Control/framework mapping (MITRE technique ids today; NIST/OWASP/etc. as the
    # compliance layer lands). A dict, e.g. {"mitre": ["T1190"], "owasp": [...]}.
    control_mapping = models.JSONField(default=dict, blank=True)
    # Where the finding was observed (endpoint, parameter, component).
    location = models.CharField(max_length=1024, blank=True)

    # A failure must be proven fixed; this drives the retest workflow.
    retest_required = models.BooleanField(default=False)

    # The original engine finding dict, kept for provenance and re-derivation.
    raw = models.JSONField(default=dict, blank=True)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "fingerprint"], name="uq_finding_deployment_fingerprint"
            ),
        ]
        indexes = [
            models.Index(fields=["deployment", "status"]),
            models.Index(fields=["severity"]),
        ]

    def __str__(self) -> str:
        return f"{self.title} [{self.severity}]"

    @property
    def evidence_class(self) -> str:
        """The finding's honest evidence class: the *weakest* class among its
        evidence rows (a chain is only as strong as its weakest link). Falls back
        to UNKNOWN when nothing is attached yet."""
        classes = [e.classification for e in self.evidence.all()]
        if not classes:
            return EvidenceClass.UNKNOWN.value
        return max(classes, key=evidence_strength)


# ---------------------------------------------------------------------------
# Evidence — graded proof behind a finding
# ---------------------------------------------------------------------------


class Evidence(models.Model):
    """A piece of proof behind a finding, graded by how strongly it is known.

    This is where the evidence-classification taxonomy (roadmap 0.3) lives as
    data rather than a display string. A finding observed by an active scan that
    reached the target is ``technically_verified``; one read from configuration is
    ``configuration_verified``; a provider claim is ``vendor_asserted``; and so
    on. ``content_hash`` gives each record simple provenance without storing
    anything sensitive verbatim."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="evidence")
    classification = models.CharField(max_length=32, choices=EvidenceClass.choices)
    summary = models.TextField(blank=True)
    # Where this evidence came from: "engine_scan", "configuration", "contract",
    # "vendor_doc", etc.
    source = models.CharField(max_length=120, blank=True)
    # Content hash for provenance (never the raw secret material).
    content_hash = models.CharField(max_length=64, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [models.Index(fields=["finding", "classification"])]

    def __str__(self) -> str:
        return f"{self.get_classification_display()} for finding {self.finding_id}"


# ---------------------------------------------------------------------------
# Unknown — a named gap in what we can verify (the Unknowns Register)
# ---------------------------------------------------------------------------


class Unknown(models.Model):
    """A thing we could not verify, tracked as a first-class managed object.

    Roadmap Phase 0.4. The discipline that keeps Mythos honest is refusing to
    turn "we couldn't confirm this" into either a clean bill or a finding. An
    Unknown is the third state: a specific question about a deployment that the
    evidence does not answer yet — *why it matters*, *what evidence would close
    it*, and *how much it moves the deployment decision*. It carries an owner and
    a review date so a gap is worked, not forgotten.

    Unknowns are derived idempotently from findings whose honest evidence class
    is unverified (see ``assurance.unknowns``), and can also be raised by hand.
    Like a finding, an Unknown is keyed within its deployment by a fingerprint so
    a re-derive updates the row rather than duplicating it, and human-set state
    (status, owner, review date, notes) survives a re-derive."""

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        INVESTIGATING = "investigating", "Investigating"
        RESOLVED = "resolved", "Resolved"
        ACCEPTED = "accepted", "Accepted as residual risk"

    class Impact(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"

    class Source(models.TextChoices):
        DERIVED = "derived", "Derived from a finding"
        MANUAL = "manual", "Raised manually"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)

    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="unknowns"
    )
    # The finding this gap was derived from, when it was. SET_NULL so resolving or
    # trimming the finding never deletes a gap a human is still working.
    finding = models.ForeignKey(
        Finding,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="unknowns",
    )

    # Stable dedup key within a deployment (hash of deployment + subject).
    fingerprint = models.CharField(max_length=64, db_index=True)

    # The three questions an Unknown must answer to be worth tracking.
    question = models.TextField()
    why_it_matters = models.TextField(blank=True)
    evidence_needed = models.TextField(blank=True)

    deployment_impact = models.CharField(
        max_length=16, choices=Impact.choices, default=Impact.MEDIUM
    )
    status = models.CharField(
        max_length=24, choices=Status.choices, default=Status.OPEN, db_index=True
    )
    source = models.CharField(
        max_length=16, choices=Source.choices, default=Source.DERIVED
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_unknowns",
    )
    # A human note that a re-derive must never clobber.
    notes = models.TextField(blank=True)
    # When this gap should be revisited if still open.
    review_by = models.DateField(null=True, blank=True)
    # True when the deriver (not a human) set this to RESOLVED because the gap
    # closed. Lets a re-derive re-open a machine-resolved gap that has come back,
    # while never touching one a human resolved or accepted.
    auto_resolved = models.BooleanField(default=False)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "fingerprint"], name="uq_unknown_deployment_fingerprint"
            ),
        ]
        indexes = [
            models.Index(fields=["deployment", "status"]),
            models.Index(fields=["deployment_impact"]),
        ]

    def __str__(self) -> str:
        return f"{self.question[:60]} [{self.get_status_display()}]"

    @property
    def is_open(self) -> bool:
        return self.status in (self.Status.OPEN, self.Status.INVESTIGATING)
