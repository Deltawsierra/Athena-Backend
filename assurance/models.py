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
from django.db.models import Q
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


# The five-way qualitative vocabulary -- Observed / Reproduced / Inferred /
# Hypothesized / Unknown -- used in research and training material, mapped onto the
# ordinal classes above. Two vocabularies for one idea drift apart the moment
# nobody writes down how they line up, and then a curriculum and a product report
# use the same word for different strengths of claim.
#
# The ORDINAL model above is canonical: it is what the code computes with, what the
# weakest-link rule ranks, and what a receipt records. The qualitative labels are a
# reading of it, never a second source of truth, which is why this maps one way
# only. Reading back would invite writing a label into a field that stores a class.
#
# The mapping is deliberately not one-to-one, because the two vocabularies do not
# carve the world the same way: "Observed" covers everything Mythos saw for itself
# (a live probe or a read of the running configuration), while everything it was
# merely told -- a document, a contract, a vendor's word -- is "Inferred", because
# it is a conclusion drawn from someone else's statement rather than an
# observation. "Reproduced" has no class of its own: reproduction is a property of
# how a finding was established (twice, independently), not of the evidence class,
# and asserting it from a class alone would be inventing a fact.
QUALITATIVE_EVIDENCE_LABELS = {
    EvidenceClass.TECHNICALLY_VERIFIED: "Observed",
    EvidenceClass.CONFIGURATION_VERIFIED: "Observed",
    EvidenceClass.DOCUMENT_SUPPORTED: "Inferred",
    EvidenceClass.CONTRACTUALLY_STATED: "Inferred",
    EvidenceClass.VENDOR_ASSERTED: "Inferred",
    EvidenceClass.PARTIALLY_VERIFIED: "Hypothesized",
    EvidenceClass.UNKNOWN: "Unknown",
    EvidenceClass.NOT_DOCUMENTED: "Unknown",
}


def qualitative_evidence_label(classification: str) -> str:
    """The qualitative reading of an evidence class, for prose and curricula.

    Unrecognised input reads as "Unknown" -- the same direction
    :func:`evidence_strength` fails in, so a label nobody defined never reads as a
    stronger claim than the evidence supports.
    """
    try:
        return QUALITATIVE_EVIDENCE_LABELS[EvidenceClass(classification)]
    except (ValueError, KeyError):
        return "Unknown"


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
        # Coverage of the SYSTEM, not strength of the evidence: parts of the
        # deployment were never assessed at all, so every fact gathered can be
        # genuine and the assessment still be incomplete. Distinct from
        # NEEDS_MORE_EVIDENCE, which is about how well the assessed parts are
        # known -- there the subject is known and the evidence is thin; here the
        # subject was never examined, which is the wider gap of the two.
        AUDIT_INCOMPLETE = "audit_incomplete", "Audit incomplete"
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
    # The monotonic revision of the decision above (Phase 2 item 5). It advances
    # by one on every ACCEPTED transition and never otherwise, so a consumer can
    # fence its reads: "I acted on revision 7" is checkable, "I acted on
    # not_recommended" is not, because the same value can be reached, left and
    # reached again.
    #
    # It exists because the decision and the claims behind it are separate rows.
    # A reader that takes them in two queries can catch the decision from after a
    # transition and the claims from before it -- a torn read that looks like a
    # perfectly ordinary answer. The revision is what makes the seam visible; see
    # `assurance.revision`.
    decision_revision = models.PositiveBigIntegerField(default=0, db_index=True)
    # Did the scan this decision rests on stop before it finished? Set by the
    # ingest from the engine's own `scan_incomplete` marker, and read as a cap by
    # `assurance.decision`: a deployment whose latest evidence is partial cannot
    # be READY, because the scanners that did not run are the ones that would
    # have found the rest. Persisted rather than passed, so a later recompute
    # from anywhere else cannot quietly restore the clean answer. Cleared by the
    # first scan that runs to completion.
    evidence_incomplete = models.BooleanField(
        default=False,
        help_text="The latest ingested scan stopped before it finished, so this "
                  "deployment's decision rests on partial evidence.",
    )
    # When a scan last ran to completion against this deployment. Null means no
    # scan has finished, which is what "not yet assessed" actually means. With it
    # set, a deployment with nothing open is genuinely READY rather than
    # unassessed -- a clean scan is a result, and the best one a customer gets.
    # Distinct from `evidence_incomplete`: a later stopped scan caps the decision
    # without erasing the fact that an earlier one finished.
    last_complete_scan_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When a scan last ran to completion against this deployment.",
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
        SKILL = "skill", "Agent skill"
        OTHER = "other", "Other"

    class Classification(models.TextChoices):
        APPROVED = "approved", "Approved"
        KNOWN = "known", "Known"
        UNMANAGED = "unmanaged", "Unmanaged"
        UNKNOWN = "unknown", "Unknown"
        HIGH_RISK = "high_risk", "High risk"
        RETIRED = "retired", "Retired but reachable"

    class ClassificationSource(models.TextChoices):
        # Who set the current classification. A machine-derived classification may
        # be moved by a later re-derive (so a host leaving scope is downgraded to
        # UNMANAGED); a human-set one is authoritative and a re-derive never touches
        # it. This is the provenance that lets discovery correct itself without
        # clobbering an operator's deliberate reclassification.
        MACHINE = "machine", "Machine-derived"
        HUMAN = "human", "Human-set"

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="assets"
    )
    kind = models.CharField(max_length=32, choices=Kind.choices, default=Kind.OTHER)
    # When something actually TESTED this asset, and what did. Observing an asset
    # is not assessing it: discovery finds that an MCP server exists, which says
    # nothing about whether anything probed it. A clean test leaves no finding, so
    # coverage cannot be read off the findings -- absence of a finding is exactly
    # the ambiguity this field removes. Null means "nothing has recorded assessing
    # this", which is never read as "assessed and clean".
    assessed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When something last assessed this asset (not merely observed it).",
    )
    assessed_by = models.CharField(
        max_length=128,
        blank=True,
        help_text="What assessed it, as the assessing engine reported itself.",
    )
    name = models.CharField(max_length=255)
    # A stable identifier for the component: an endpoint URL, ARN, tool name, etc.
    identifier = models.CharField(max_length=1024, blank=True)
    provider = models.ForeignKey(
        Provider, on_delete=models.SET_NULL, null=True, blank=True, related_name="assets"
    )
    classification = models.CharField(
        max_length=32, choices=Classification.choices, default=Classification.KNOWN
    )
    classification_source = models.CharField(
        max_length=16,
        choices=ClassificationSource.choices,
        default=ClassificationSource.MACHINE,
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
        # A control limits a specific path, but the underlying defect is still
        # there. Distinct from REMEDIATING, which says a fix is in progress: a
        # contained finding may have no fix in progress at all, and reporting it as
        # REMEDIATING would claim work nobody is doing. Never resolved.
        CONTAINED = "contained", "Contained (defect not removed)"
        # A premise behind an earlier decision changed or became unreliable, so the
        # finding's severity and evidence can no longer be trusted as they stand.
        # Distinct from OPEN, which says a fresh, undecided case: this one WAS
        # decided, and the ground moved under it.
        INVALIDATED = "invalidated", "Invalidated (premise no longer holds)"
        CLOSED = "closed", "Verified closed"
        ACCEPTED = "accepted", "Accepted risk"
        FALSE_POSITIVE = "false_positive", "False positive"

    # What each status must NOT be read as. Two of these states exist because the
    # existing ones were being stretched to cover them, and a state whose wrong
    # reading is obvious to whoever added it is not obvious to a reader six months
    # later looking at a report. Carried as data so the API and the dashboard show
    # the same caveat rather than each inventing one.
    MUST_NOT_IMPLY = {
        Status.CONTAINED: "The defect has not been removed. A control limits one path to "
        "it; the weakness itself is still present, and no fix is implied.",
        Status.INVALIDATED: "No exploitation is implied, and no fix is implied. The "
        "premise behind the earlier assessment changed, so the finding needs "
        "re-assessing -- it is not a confirmed incident and not a closed case.",
        Status.REMEDIATING: "A fix being in progress is not a fix being done, and not a "
        "risk being contained in the meantime.",
        Status.ACCEPTED: "Accepted is a human decision to carry the risk, not evidence "
        "that the risk is small.",
    }

    class RemediationState(models.TextChoices):
        """Where the *fix* is in the human remediation workflow (Phase 2.3).

        This is a **separate axis** from ``Status`` above. ``Status`` is the
        security disposition — is the risk still live? ``RemediationState`` is
        the ticket-like process of getting a human to fix it. The two must never
        be conflated: a finding is only *securely* resolved via ``Status``
        (CLOSED / ACCEPTED / FALSE_POSITIVE); reaching ``RESOLVED`` here is a
        process claim ("someone says the work is done"), not proof the risk is
        gone. Legal moves between these states are enforced in
        ``assurance.remediation``; illegal jumps are rejected, not coerced."""

        NEW = "new", "New"
        TRIAGED = "triaged", "Triaged"
        IN_PROGRESS = "in_progress", "In progress"
        IN_REVIEW = "in_review", "In review"
        RESOLVED = "resolved", "Resolved"
        WONT_FIX = "wont_fix", "Won't fix"

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
    # Nullable with NO default. A 0.5 default is false precision: it is a number
    # nobody computed, indistinguishable in every report and every API response
    # from a real 0.5 that a detector actually measured. The Claims engine already
    # returns None rather than a number for an unknown confidence; this is the
    # older model catching up with the discipline the rest of the platform is built
    # on. Null means "not known", and null is never rendered as a figure.
    confidence = models.FloatField(null=True, blank=True)
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

    # --- Remediation workflow (Phase 2.3) — the *human process* of getting this
    # finding fixed, tracked ORTHOGONALLY to ``status`` above. ``status`` is the
    # security disposition (is the risk still live?); ``remediation_state`` is
    # where the fix sits in the human workflow, and ``assignee`` is who is doing
    # that work. ``owner`` stays the person accountable for the disposition (who
    # moves ``status``); ``assignee`` is the distinct person doing the fix — the
    # two axes are kept separate on purpose. Every change here is attributed via
    # ``RemediationEvent`` and gated through ``assurance.remediation``; none of it
    # ever touches ``status`` or the deployment decision.
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_findings",
    )
    remediation_state = models.CharField(
        max_length=24,
        choices=RemediationState.choices,
        default=RemediationState.NEW,
        db_index=True,
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


# A finding a human has dispositioned is no longer the machine's to move: the
# derivers that create, refresh and auto-resolve machine-owned rows all stop at
# this boundary. Defined once here, beside the statuses themselves, because three
# modules asked the same question and two of them had their own copy of the
# answer — which is how the derivers drift apart without anyone noticing.
RESOLVED_FINDING_STATUSES = frozenset(
    {Finding.Status.CLOSED, Finding.Status.ACCEPTED, Finding.Status.FALSE_POSITIVE}
)

# Statuses whose severity can no longer be trusted as it stands: the finding is
# neither resolved nor a live weakness at a known severity. An INVALIDATED finding
# drives "needs more evidence", because its premise moved -- reporting its old
# severity would be reporting a number the evidence no longer supports, and
# dropping it would be reporting a clean bill nobody established.
#
# CONTAINED is deliberately NOT here: a contained finding's severity is still
# exactly what it was. What changed is that one path to it is limited, which is not
# the same as the defect being smaller.
UNTRUSTED_SEVERITY_STATUSES = frozenset({Finding.Status.INVALIDATED})


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
# RemediationEvent — one attributed step in a finding's remediation workflow
# ---------------------------------------------------------------------------


class RemediationEvent(models.Model):
    """One attributed step in a finding's remediation workflow (Phase 2.3).

    Every assignment and every workflow-state change on a finding writes one of
    these, so the human remediation *process* is a durable, attributed audit
    trail — who moved it, from where to where, and why. It reuses the actor +
    note + ordered-timestamp attribution pattern the failsafe control plane
    already established (:class:`failsafe.models.FailsafeAuditEvent`) rather than
    inventing a second attribution mechanism.

    This log is about the process, never the security disposition: a ``to_state``
    of RESOLVED records that a human called the remediation work done, not that
    the finding is securely closed (that remains ``Finding.status``). An event
    where ``from_state == to_state`` marks an assignment or a note that did not
    move the workflow. ``from_state`` is blank only for a synthetic seed event."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    finding = models.ForeignKey(
        Finding, on_delete=models.CASCADE, related_name="remediation_events"
    )
    from_state = models.CharField(
        max_length=24, choices=Finding.RemediationState.choices, blank=True
    )
    to_state = models.CharField(max_length=24, choices=Finding.RemediationState.choices)
    # Who made the change. SET_NULL so removing a user never deletes the trail; a
    # null actor reads as "no longer attributable", never as "no one did it".
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="remediation_events",
    )
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [models.Index(fields=["finding", "created_at"])]

    def __str__(self) -> str:
        return f"{self.from_state or '∅'} → {self.to_state} on finding {self.finding_id}"


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

    Unknowns are derived idempotently from two sources (see
    ``assurance.unknowns``) — findings whose honest evidence class is unverified,
    and provider postures the data-boundary assessment could not assess because
    nobody declared them — and can also be raised by hand. The second source
    matters because a gap with no finding behind it is exactly the one a
    findings-only register reports as zero.
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
        POSTURE = "posture", "Derived from an undeclared provider posture"
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

    # What this gap is *about*, as a slug: ``prompt-injection`` for an unconfirmed
    # prompt-injection finding, ``training-posture`` for an undeclared provider
    # posture. A label, not a key — the fingerprint is the dedup key, and two gaps
    # of the same kind legitimately share a subject. It exists so a consumer
    # outside this database (a report, an export, a benchmark answer key) can name
    # a kind of gap without carrying a hash or an auto-increment id around.
    subject = models.CharField(max_length=200, blank=True, db_index=True)

    # Stable dedup key within a deployment (hash of the namespaced subject).
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


# ---------------------------------------------------------------------------
# DataBoundary — the approved data-flow boundary for a deployment (Phase 1.4)
# ---------------------------------------------------------------------------


class DataBoundary(models.Model):
    """The data boundary a customer *approves* for a deployment — the other half
    of the AI Data Boundary Assessment (Phase 1.4).

    Assurance discovery already knows the deployment's **actual** data
    destinations: the providers and components it depends on (assets → providers,
    Phase 1.1/1.2/1.6) and each one's declared posture (region, retention,
    training, subprocessors — the Provider Assurance Profile, Phase 1.5). What was
    missing is the **approved** side: what the customer says the system *may* do
    with data. This row holds that declaration, so ``assurance.boundary`` can
    reconcile approved-vs-actual and surface where they disagree.

    Defaults are the safe ones: training on customer data and third-party sharing
    are **not** approved unless a human says so, so an undeclared boundary never
    reads as permission. An empty ``allowed_regions`` means no region restriction
    has been declared (any region is in-boundary), which the assessment reports as
    *not assessed* rather than *approved*."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.OneToOneField(
        Deployment, on_delete=models.CASCADE, related_name="data_boundary"
    )
    # The regions data is approved to be processed in (e.g. ["eu-west-1", "eu"]).
    # Empty = no region restriction declared (not the same as "all approved").
    allowed_regions = models.JSONField(default=list, blank=True)
    # Whether the system is approved to have its data trained on, or shared with
    # third parties / subprocessors. Off by default: silence is not consent.
    training_allowed = models.BooleanField(default=False)
    third_party_sharing_allowed = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="data_boundaries",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Data boundary for {self.deployment.name}"


# ---------------------------------------------------------------------------
# AssuranceClaim — a version-bound, falsifiable assurance statement (SPINE)
# ---------------------------------------------------------------------------


class DecisionTransition(models.Model):
    """One accepted change of a deployment's decision — the outbox row.

    Written in the same transaction as the decision it records (see
    :func:`assurance.revision.accept_transition`), so the pair cannot come apart:
    a decision whose transition is missing, or a transition whose decision never
    landed, cannot both exist and be observed.

    It is also the only durable answer to "how did we get here". The deployment
    carries one decision; a deployment that went READY → NOT_RECOMMENDED → READY
    looks identical to one that was always READY, and the difference is the whole
    story. ``basis_digest`` carries what the decision was computed from, so two
    agreeing decisions can still be told apart by the evidence behind them.
    """

    id = models.BigAutoField(primary_key=True)
    deployment = models.ForeignKey(
        "Deployment", on_delete=models.CASCADE, related_name="decision_transitions"
    )
    # Monotonic per deployment, matching `Deployment.decision_revision` after this
    # transition committed. Unique per deployment, which is what makes a duplicate
    # or a skipped revision a database error rather than a silent inconsistency.
    revision = models.PositiveBigIntegerField()
    # Empty string, not null, for "there was no decision before this" — an
    # unassessed deployment has no decision, and that is a real starting state
    # rather than missing data.
    from_decision = models.CharField(max_length=32, blank=True)
    to_decision = models.CharField(max_length=32, blank=True)
    # What the decision was computed from (a receipt digest, a claim-state
    # digest). Blank when the caller did not supply one — recorded as absent
    # rather than as a digest of nothing.
    basis_digest = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # When a downstream consumer confirmed it had processed this transition. Null
    # means not yet, which is never read as "delivered and uneventful".
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["deployment_id", "revision"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "revision"], name="uq_decision_transition_revision"
            ),
        ]
        indexes = [models.Index(fields=["deployment", "revision"])]

    def __str__(self) -> str:
        return (
            f"{self.deployment_id} r{self.revision}: "
            f"{self.from_decision or '∅'} -> {self.to_decision or '∅'}"
        )


class AssuranceClaimQuerySet(models.QuerySet):
    """Where "current" is defined, once.

    Eight call sites used to spell ``valid_to__isnull=True`` by hand to mean
    current. That was correct while the model had one temporal axis and becomes a
    silent defect with two: a retroactive claim is still *believed* (``valid_to``
    null) while describing a window that has closed, so a hand-rolled filter would
    return it as the deployment's live claim and a decision would be computed from
    a fact about last week.

    So the definition lives here and the call sites ask for it. A test greps
    ``assurance/`` for hand-rolled currency filters, because the failure mode of
    one site being missed is invisible: the query still runs and still returns
    rows.
    """

    def current(self):
        """The live version of each claim identity: believed now AND effective now."""
        return self.filter(valid_to__isnull=True, effective_to__isnull=True)

    def believed_now(self):
        """Everything Mythos currently holds, retroactive claims included.

        Distinct from :meth:`current` and rarely what a decision wants. It is what
        an auditor asking "what does Mythos believe today, about any period" needs,
        and naming it separately is what stops that question being answered with
        the current-claims query or the other way round.
        """
        return self.filter(valid_to__isnull=True)

    def effective_at(self, when):
        """Every version whose EFFECTIVE window contains ``when`` -- what was true
        of the world at that moment, whenever we happened to learn it."""
        return self.filter(effective_from__lte=when).filter(
            Q(effective_to__isnull=True) | Q(effective_to__gt=when)
        )


class AssuranceClaim(models.Model):
    """A positive, falsifiable *statement* an auditor can carry, re-verify, and
    watch expire — the SPINE Phase 1 gap the record did not fill.

    A :class:`Finding` is a negative observation. An **AssuranceClaim** is the
    other side: a positive claim ("this deployment's data destinations are all
    within the approved EU boundary", "the agent's effective access is
    least-privilege") bound to a specific system state (``system_fingerprint``),
    the rule-set version it was evaluated under (``policy_version``), and an
    ``environment``. It is honest by construction, and enforces the invariants the
    rest of the assurance layer lives by:

    1. **Version-bound.** A claim is true *of a system state*. A change in
       ``system_fingerprint`` does not mutate the claim in place — it SUPERSEDES
       the old version (``valid_to`` set, status ``SUPERSEDED``) and opens a new
       current one, so history is append-only and never rewritten.
    1b. **Bitemporal.** Two independent axes, because "when this was true" and
       "when Mythos learned it" are different facts and a single axis silently
       conflates them. ``valid_from``/``valid_to`` are the **recorded** axis: the
       window during which this version was Mythos's current belief.
       ``effective_from``/``effective_to`` are the **effective** axis: the window
       during which the state it describes actually held. A claim is CURRENT only
       when it is both currently believed and currently effective, so a
       late-arriving observation about a window that has already closed is
       recorded as history rather than overwriting today's claim. See
       :meth:`AssuranceClaimQuerySet.current`.
    2. **Never a fabricated pass.** ``confidence`` is ``None`` when the claim is
       UNKNOWN — never ``0.0`` read as a passing score.
    3. **Unknown/contradicted/stale never coerced to verified.** The lifecycle
       (see :mod:`assurance.claims`) refuses any transition into VERIFIED that is
       not backed by verified evidence, and staleness moves a claim *away* from a
       pass, never toward one.
    4. **Vendor claims cannot read VERIFIED.** ``vendor_asserted`` is true when the
       strongest supporting evidence is still vendor-asserted-or-weaker; such a
       claim caps at SUPPORTED, and a human cannot hand-verify it.
    5. **A claim is only as strong as its weakest evidence.** ``evidence_class`` is
       the weakest supporting class behind the claim (the same weakest-link
       discipline :attr:`Finding.evidence_class` uses).
    6. **Attributed lifecycle.** Every status change is a :class:`ClaimEvent` with
       an actor, so who moved a claim, from where to where, is durable and never
       silently coerced.
    """

    class ClaimType(models.TextChoices):
        DATA_BOUNDARY = "data_boundary", "Data boundary"
        EFFECTIVE_ACCESS = "effective_access", "Effective access"
        AI_BOM = "ai_bom", "AI bill of materials"

    class ClaimStatus(models.TextChoices):
        DRAFT = "draft", "Draft"
        SUPPORTED = "supported", "Supported"
        VERIFIED = "verified", "Verified"
        PARTIALLY_VERIFIED = "partially_verified", "Partially verified"
        CONTRADICTED = "contradicted", "Contradicted"
        UNKNOWN = "unknown", "Unknown"
        STALE = "stale", "Stale"
        SUPERSEDED = "superseded", "Superseded"
        REVOKED = "revoked", "Revoked"

    objects = AssuranceClaimQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)

    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="assurance_claims"
    )
    # The optional subject of the claim: a specific component it is about. SET_NULL
    # so retiring an asset never deletes the durable claim history.
    asset = models.ForeignKey(
        Asset,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assurance_claims",
    )

    claim_type = models.CharField(max_length=32, choices=ClaimType.choices)
    statement = models.TextField()

    # The STABLE claim-identity key: sha256(deployment.uuid | claim_type |
    # subject_key). The same across every version of the same claim, so a
    # re-derive finds the current version rather than duplicating it.
    fingerprint = models.CharField(max_length=64, db_index=True)
    # The system state this claim was observed true of. A CHANGE here versions the
    # claim (supersede + new current version); it is never a dedup key on its own.
    system_fingerprint = models.CharField(max_length=64)
    # The rule-set / evaluator version the claim was assessed under (= the receipt
    # standard version), so a consumer knows which policy produced this result.
    policy_version = models.CharField(max_length=120)
    # The environment, copied from the deployment at derivation so a claim carries
    # the context it was made in even if the deployment is later re-homed.
    environment = models.CharField(max_length=32, choices=Deployment.Environment.choices)

    status = models.CharField(
        max_length=32, choices=ClaimStatus.choices, default=ClaimStatus.DRAFT, db_index=True
    )
    # The WEAKEST supporting evidence class (invariant 5). Defaults to UNKNOWN so a
    # claim with no assessed basis never reads as strongly evidenced.
    evidence_class = models.CharField(
        max_length=32, choices=EvidenceClass.choices, default=EvidenceClass.UNKNOWN
    )
    # None when unknown — NEVER 0.0 read as a passing score (invariant 2).
    confidence = models.FloatField(null=True, blank=True)
    # True when the strongest supporting evidence is still vendor-asserted-or-weaker
    # — such a claim may not read VERIFIED (invariant 4).
    vendor_asserted = models.BooleanField(default=False)

    # The standing six-state decision echo, None-safe: an unassessed deployment has
    # no decision, and an absent decision is never read as "ready".
    assessment = models.CharField(
        max_length=32, choices=Deployment.Decision.choices, null=True, blank=True
    )

    # Honest, non-sensitive narrative — NEVER raw payloads, secrets, or target
    # material. What supports the claim, and what contradicts it.
    supporting_summary = models.TextField(blank=True)
    contradicting_summary = models.TextField(blank=True)
    # The conditions that would falsify this claim (what to watch for), as a list
    # of short strings. A falsifiable claim names how it could be proven wrong.
    invalidation_conditions = models.JSONField(default=list, blank=True)

    # The version that replaced this one, once superseded. SET_NULL so trimming a
    # newer version never deletes the older row's identity.
    superseded_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="supersedes",
    )
    # The human accountable for this claim. A re-derive never clobbers it.
    human_owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_claims",
    )
    # The deployment assurance-receipt digest at the time the claim was (last)
    # derived — provenance binding the claim to the evidence state behind it.
    receipt_digest = models.CharField(max_length=64, blank=True)

    # The RECORDED axis: the window during which this version was Mythos's
    # current belief. `valid_to` null means Mythos still believes it. It is set at
    # derivation and closed at supersession, so it tracks knowledge, not the world
    # -- which is why the pair below exists rather than these two being read as
    # both. (They were commented "Bitemporal validity" while being a single axis;
    # that is the conflation this pair removes.)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_to = models.DateTimeField(null=True, blank=True)

    # The EFFECTIVE axis: the window during which the state this claim describes
    # actually held. Defaults to "began when we recorded it, still holding", which
    # is the honest reading for an ordinary derive: we observed it now and have no
    # evidence about earlier. A retroactive observation -- something learned today
    # about a window that closed yesterday -- sets `effective_to`, which is exactly
    # what keeps it out of the current slot.
    effective_from = models.DateTimeField(default=timezone.now)
    effective_to = models.DateTimeField(null=True, blank=True)

    verified_at = models.DateTimeField(null=True, blank=True)
    expiration = models.DateTimeField(null=True, blank=True)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        constraints = [
            # Only ONE CURRENT version per claim identity -- current meaning
            # currently believed AND currently effective. Superseded versions
            # (valid_to set) and retroactive ones (effective_to set) are both
            # exempt, keeping full history on both axes.
            #
            # The effective half is what lets a late-arriving observation be
            # recorded at all: without it, a claim learned today about a window
            # that closed yesterday would collide with today's claim on this
            # constraint, and the only ways out would be to overwrite today's
            # claim or to drop the observation. Both lose a fact.
            models.UniqueConstraint(
                fields=["deployment", "fingerprint"],
                condition=Q(valid_to__isnull=True) & Q(effective_to__isnull=True),
                name="uq_current_claim",
            ),
        ]
        indexes = [
            models.Index(fields=["deployment", "status"]),
            models.Index(fields=["deployment", "claim_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.get_claim_type_display()}: {self.get_status_display()}"

    @property
    def is_stale(self) -> bool:
        """Whether a CURRENT claim's evidence has expired — last observed longer
        ago than :data:`assurance.change.EVIDENCE_TTL_DAYS`, so a re-verify is due
        before it is read as current. A superseded version is history, not a live
        claim, so it is never itself "stale"."""
        from .change import EVIDENCE_TTL_DAYS, age_days

        if self.valid_to is not None:
            return False
        days = age_days(self, timezone.now())
        return days is not None and days >= EVIDENCE_TTL_DAYS


# ---------------------------------------------------------------------------
# ClaimEvent — one attributed step in an assurance claim's lifecycle (SPINE)
# ---------------------------------------------------------------------------


class ClaimEvent(models.Model):
    """One attributed lifecycle step of an :class:`AssuranceClaim`.

    Every status change on a claim — a machine derivation, a human transition, a
    supersede, a revoke — writes one of these, so a claim's lifecycle is a durable,
    attributed audit trail: who moved it, from where to where, and why. It mirrors
    :class:`RemediationEvent` exactly rather than inventing a second attribution
    mechanism. ``from_status`` is blank only for a synthetic seed event (a claim's
    first appearance, ``∅ → status``); ``actor`` is null for a machine derivation,
    which reads as "not human-attributed", never as "no one did it"."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    claim = models.ForeignKey(
        AssuranceClaim, on_delete=models.CASCADE, related_name="events"
    )
    from_status = models.CharField(
        max_length=32, choices=AssuranceClaim.ClaimStatus.choices, blank=True
    )
    to_status = models.CharField(
        max_length=32, choices=AssuranceClaim.ClaimStatus.choices
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="claim_events",
    )
    note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [models.Index(fields=["claim", "created_at"])]

    def __str__(self) -> str:
        return f"{self.from_status or '∅'} → {self.to_status} on claim {self.claim_id}"


# ---------------------------------------------------------------------------
# RetestRequirement — a claim invalidated by a change owes a retest (SPINE)
# ---------------------------------------------------------------------------


class RetestRequirement(models.Model):
    """An open obligation to re-test a claim because the system it was true *of*
    has changed — the SPINE Phase 2 temporal / INVALIDATES backbone.

    A :class:`AssuranceClaim` is true of a system state (``system_fingerprint``).
    When a change moves that state, the claim's evidence no longer reflects what is
    running: a retest is due before the claim may be read as current. Rather than
    silently flip a status — and never a fabricated "still passes" — that obligation
    is recorded here as a **durable, attributed fact**: which claim was invalidated,
    why (``reason``), when it opened, who opened it (``actor``, null = the machine),
    and — once a fresh derivation rebinds the claim to the new state — the new claim
    version that satisfied it (``resolving_claim``) and when (``resolved_at``).

    It mirrors :class:`RemediationEvent` / :class:`ClaimEvent`'s attribution pattern
    (actor + note + ordered timestamps) rather than inventing a second mechanism,
    and it is honest by construction:

    - Opening a requirement never itself reads as a pass; the invalidated claim is
      moved *away* from a pass (marked STALE — "a retest is due") through the
      existing Phase 1 seam, never to a new "invalid but passing" state.
    - Only ONE requirement is open per claim identity at a time (the partial unique
      constraint below plus the engine's idempotence guard), so re-running the
      invalidation engine never opens a duplicate obligation.
    - A requirement is resolved only when a fresh :func:`assurance.claims.derive_claims`
      produces a new current version bound to the changed state — a machine no
      longer flagging drift is not proof of a retest; a re-derivation that rebinds
      is. ``resolving_claim`` records exactly which version answered it.

    The ``claim`` FK points at the *version that was invalidated* (a durable record
    of what drifted); ``resolving_claim`` is SET_NULL so trimming a newer version
    never deletes the obligation's history."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # The owning deployment — CASCADE, so the obligation lives and dies with the
    # system under assurance, and reads scope on it exactly like the other rows.
    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="retest_requirements"
    )
    # The claim version that was invalidated. CASCADE, mirroring ClaimEvent's
    # owning relationship to its claim: the obligation is *about* this claim.
    claim = models.ForeignKey(
        AssuranceClaim, on_delete=models.CASCADE, related_name="retest_requirements"
    )
    # The new current version that satisfied the retest, once a fresh derivation
    # rebound the claim to the changed state. SET_NULL so trimming that newer
    # version never deletes this durable obligation; null while still open.
    resolving_claim = models.ForeignKey(
        AssuranceClaim,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="resolves_retests",
    )
    # Why the retest is owed, in honest, non-sensitive words (e.g. "System
    # fingerprint changed"). Never raw payloads, secrets, or target material.
    reason = models.TextField(blank=True)
    # The system fingerprint that TRIGGERED the retest — the changed state the
    # claim must be re-evaluated against. Provenance, binding the obligation to the
    # state drift that opened it, the way a claim binds to its system_fingerprint.
    triggering_system_fingerprint = models.CharField(max_length=64, blank=True)
    # Who opened it. SET_NULL so removing a user never deletes the trail; null
    # reads as "the machine opened this", never as "no one did it".
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="opened_retest_requirements",
    )
    opened_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-opened_at"]
        constraints = [
            # At most ONE OPEN retest requirement per invalidated claim version, so
            # re-running the invalidation engine never opens a duplicate obligation
            # for the same open drift. Resolved rows (resolved_at set) are exempt,
            # keeping full history — and the engine's identity-level idempotence
            # guard (assurance.invalidation) covers the same claim across versions.
            models.UniqueConstraint(
                fields=["claim"],
                condition=Q(resolved_at__isnull=True),
                name="uq_open_retest_per_claim",
            ),
        ]
        indexes = [
            models.Index(fields=["deployment", "resolved_at"]),
            models.Index(fields=["claim", "resolved_at"]),
        ]

    def __str__(self) -> str:
        state = "open" if self.resolved_at is None else "resolved"
        return f"Retest [{state}] for claim {self.claim_id}"

    @property
    def is_open(self) -> bool:
        """Whether the obligation is still outstanding — no fresh derivation has
        yet rebound the claim to the changed state and satisfied it."""
        return self.resolved_at is None


# ---------------------------------------------------------------------------
# DeclaredComponent — the customer's declared architecture (SPINE Stage 3)
# ---------------------------------------------------------------------------


class DeclaredComponent(models.Model):
    """One component the customer *declares* their AI system is built from.

    The AI-BOM (:func:`assurance.bom.build_ai_bom`) enumerates the **observed**
    architecture — every component discovery actually found. A DeclaredComponent is
    the other half: what the customer says *should* be there. Comparing the two
    (:func:`assurance.bom_drift.assess_bom_drift`) is how SPINE surfaces drift —
    "declared 3 tools / 1 provider / 1 MCP server, observed 5 tools / a fallback
    provider / 3 MCP servers" — and turns an undeclared (shadow) component into a
    finding and a contradiction of the "the BOM enumerates the full supply chain"
    claim.

    It mirrors :class:`Asset`'s taxonomy (same ``Kind``) and dedup key
    (deployment + kind + identifier) so declared and observed match on the same
    identity. The provider is named, not linked: a declaration is what the customer
    asserts, which may reference a vendor no :class:`Provider` row exists for yet.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="declared_components"
    )
    # Same taxonomy as the observed Asset, so declared and observed compare on a
    # shared vocabulary.
    kind = models.CharField(max_length=32, choices=Asset.Kind.choices, default=Asset.Kind.OTHER)
    name = models.CharField(max_length=255)
    # The declared component's stable identity (endpoint, ARN, tool name, ...),
    # matched against the observed asset's ``identifier``. Blank falls back to name.
    identifier = models.CharField(max_length=1024, blank=True)
    # The vendor the customer declares behind this component, by name — a
    # declaration references what the customer asserts, not necessarily a Provider
    # row that exists yet.
    provider_name = models.CharField(max_length=255, blank=True)
    note = models.TextField(blank=True)
    # Who declared it, kept for provenance. SET_NULL so removing a user never
    # deletes the declaration.
    declared_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="declared_components",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["deployment", "kind", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "kind", "identifier"],
                name="uq_declared_deployment_kind_identifier",
            ),
        ]
        indexes = [models.Index(fields=["deployment", "kind"])]

    def __str__(self) -> str:
        return f"declared {self.name} ({self.get_kind_display()})"


# ---------------------------------------------------------------------------
# Commercial spine — per-tenant external-integration bindings
# ---------------------------------------------------------------------------
#
# A Deployment is the tenant boundary in this system of record: it is the unit a
# customer contract expands on, and every finding, asset and decision already
# hangs off it. So a "per-tenant" connector / posture binding is a per-deployment
# row — the deployment IS the tenant. The two bindings below carry the endpoint a
# connector or posture domain points at, in the clear, and the credential that
# reaches it, ENCRYPTED AT REST via :mod:`assurance.crypto`. The plaintext secret
# never lives in a column, never appears in ``endpoint``, and is decrypted only in
# memory at point of use. With no ``ASSURANCE_CREDENTIAL_KEY`` configured no secret
# can be stored at all, so every binding stays inert — the honesty invariant that
# an unconfigured environment behaves exactly as it does today.


class _CredentialBinding(models.Model):
    """Shared base for a per-deployment external-integration binding: the
    non-secret endpoint config, plus one encrypted credential. Abstract — the
    concrete bindings name their target (a connector, a posture domain) and how to
    build the target's config from ``endpoint`` + the decrypted secret."""

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    # Whether this binding is live. A disabled binding is inert (no push, no fetch)
    # exactly like an unconfigured one — a reversible off switch that keeps the
    # credential on file.
    enabled = models.BooleanField(default=True)
    # The non-secret endpoint / scoping fields (base URL, project key, table,
    # owner/repo, account, organisation, ...). NEVER the credential — the secret
    # rides only in ``secret_ciphertext`` and only ever encrypted.
    endpoint = models.JSONField(default=dict, blank=True)
    # The credential, Fernet-encrypted (see :mod:`assurance.crypto`). Blank means
    # "no credential on file". A plaintext secret is never written here.
    secret_ciphertext = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    # -- secret handling (encrypted at rest, never in the clear) -----------

    @property
    def has_secret(self) -> bool:
        """Whether a credential is on file — the only thing an API ever reveals
        about the secret. Never the value itself."""
        return bool(self.secret_ciphertext)

    def set_secret(self, plaintext: str | None) -> None:
        """Encrypt and store a credential (or clear it when ``plaintext`` is
        falsy). Raises :class:`assurance.crypto.EncryptionUnavailable` when no key
        is configured, so a secret is never silently persisted in the clear — the
        caller checks :func:`assurance.crypto.encryption_available` first and keeps
        the binding inert instead."""
        from .crypto import encrypt_secret

        if plaintext:
            self.secret_ciphertext = encrypt_secret(plaintext)
        else:
            self.secret_ciphertext = ""

    def get_secret(self) -> str | None:
        """Decrypt the stored credential, in memory, at point of use. ``None`` when
        there is none, no key is configured, or the ciphertext cannot be decrypted
        (retired key / tampering) — every one of which leaves the binding inert."""
        from .crypto import decrypt_secret

        return decrypt_secret(self.secret_ciphertext or None)

    def __str__(self) -> str:  # never includes the secret
        target = getattr(self, self._target_field)
        state = "enabled" if self.enabled else "disabled"
        return f"{target} binding for {self.deployment_id} ({state})"


class ConnectorBinding(_CredentialBinding):
    """Per-deployment binding of one outbound connector to its endpoint + encrypted
    credential. This is what makes a connector *live* for a tenant: with an
    operational binding the manual push and the automated dispatch use it; with
    none (the default) the connector is inert exactly as it is today."""

    _target_field = "connector"

    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="connector_bindings"
    )
    # The connector registry name (``"jira"``, ``"servicenow"``, ...). Validated in
    # :meth:`clean` against the live registry rather than a frozen choices list, so
    # the two can never drift.
    connector = models.CharField(max_length=64)

    class Meta:
        ordering = ["deployment", "connector"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "connector"], name="uq_connector_binding_deployment"
            )
        ]
        indexes = [models.Index(fields=["deployment", "connector"])]

    def clean(self) -> None:
        from django.core.exceptions import ValidationError

        from .connectors import UnknownConnector, get_connector_class

        try:
            get_connector_class(self.connector)
        except UnknownConnector as exc:
            raise ValidationError({"connector": str(exc)}) from None

    def connector_class(self):
        from .connectors import get_connector_class

        return get_connector_class(self.connector)

    def build_config(self):
        """The connector's frozen config from this binding: endpoint fields + the
        decrypted secret. When no usable secret is available the config reports
        not-configured, so the connector stays inert."""
        return self.connector_class().config_from_binding(self.endpoint or {}, self.get_secret())

    def build_connector(self):
        from .connectors import build_connector

        return build_connector(self.connector, self.build_config())

    def is_operational(self) -> bool:
        """Whether this binding yields a *configured* connector — enabled, a
        decryptable credential on file, and every required endpoint field present.
        This is the per-tenant ``configured`` state the API reports and the gate the
        dispatcher checks before it ever touches a transport."""
        if not self.enabled:
            return False
        try:
            return bool(self.build_config().is_configured())
        except Exception:  # noqa: BLE001 — an unbuildable config is simply inert
            return False


class PostureBinding(_CredentialBinding):
    """Per-deployment binding of one posture domain (cloud / secrets / repo) to a
    real resource URL + encrypted read-credential. With an operational binding the
    posture read fetches and evaluates the live resource; with none (the default)
    the domain is inert — ``connected: false`` and the catalog only, exactly as
    today."""

    _target_field = "domain"

    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="posture_bindings"
    )
    # The posture-domain registry name (``"cloud"``, ``"secrets"``, ``"repo"``).
    domain = models.CharField(max_length=64)

    class Meta:
        ordering = ["deployment", "domain"]
        constraints = [
            models.UniqueConstraint(
                fields=["deployment", "domain"], name="uq_posture_binding_deployment"
            )
        ]
        indexes = [models.Index(fields=["deployment", "domain"])]

    def clean(self) -> None:
        from django.core.exceptions import ValidationError

        from .posture import UnknownPostureDomain, get_assessment_class

        try:
            get_assessment_class(self.domain)
        except UnknownPostureDomain as exc:
            raise ValidationError({"domain": str(exc)}) from None

    def domain_class(self):
        from .posture import get_assessment_class

        return get_assessment_class(self.domain)

    def build_config(self):
        return self.domain_class().config_from_binding(self.endpoint or {}, self.get_secret())

    def build_assessment(self):
        from .posture import build_assessment

        return build_assessment(self.domain, self.build_config())

    def is_operational(self) -> bool:
        if not self.enabled:
            return False
        try:
            return bool(self.build_config().is_configured())
        except Exception:  # noqa: BLE001
            return False


class DispatchPolicy(models.Model):
    """The per-tenant automated-dispatch policy: when a qualifying finding appears
    (or the deployment's decision enters a blocking state) its evidence is
    auto-dispatched to the deployment's operational connectors.

    OFF by default and per deployment: with no policy, or a policy left disabled,
    nothing auto-dispatches — the manual admin push stays the only outbound path,
    exactly as today. Turning it on is a deliberate per-tenant step."""

    id = models.BigAutoField(primary_key=True)
    deployment = models.OneToOneField(
        Deployment, on_delete=models.CASCADE, related_name="dispatch_policy"
    )
    # Off unless explicitly enabled — the honesty default (no surprise outbound).
    enabled = models.BooleanField(default=False)
    # A finding at or above this severity qualifies for dispatch.
    min_severity = models.CharField(
        max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_HIGH
    )
    # Also dispatch a deployment's qualifying findings when its decision enters a
    # blocking state (needs remediation / not recommended / paused).
    on_blocking_decision = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def finding_qualifies(self, finding) -> bool:
        """Whether a finding meets the severity threshold. Info-severity findings
        never qualify (they are not dispatched upstream)."""
        return severity_rank(finding.severity) >= severity_rank(self.min_severity)

    def __str__(self) -> str:
        state = "enabled" if self.enabled else "disabled"
        return f"dispatch policy for {self.deployment_id} ({state}, >= {self.min_severity})"


class DispatchAttempt(models.Model):
    """The auditable record of an automated (or manual) dispatch of one finding to
    one connector. One row per ``(finding, connector)`` — the idempotency key: once
    an attempt is :attr:`Outcome.SENT` it is terminal and the finding is never
    pushed to that connector again. A not-yet-sent record (inert / disabled / no
    key / failed) is retried on the next qualifying trigger and updated in place,
    with ``attempts`` counting how many times it has been tried. The ``detail`` is
    always a human-readable line and NEVER carries a secret."""

    class Outcome(models.TextChoices):
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"
        # The provider may have committed this before the client lost the answer.
        # Neither SENT nor FAILED is true: recording it as FAILED licenses a retry
        # that creates the ticket twice, and recording it as SENT claims a ticket
        # that may not exist. It stays here until reconciliation resolves it.
        UNKNOWN = "unknown", "Unknown — may have been committed"
        SKIPPED_INERT = "skipped_inert", "Skipped — connector not configured"
        SKIPPED_NO_KEY = "skipped_no_key", "Skipped — no encryption key"
        SKIPPED_DISABLED = "skipped_disabled", "Skipped — binding disabled"

    class Trigger(models.TextChoices):
        SEVERITY = "severity", "Finding severity threshold"
        BLOCKING_DECISION = "blocking_decision", "Blocking decision transition"
        MANUAL = "manual", "Manual dispatch"

    #: Outcomes that mean the external system accepted the push — terminal.
    TERMINAL_OUTCOMES = frozenset({Outcome.SENT})

    #: Outcomes whose truth is not known. NOT terminal (nothing was confirmed) and
    #: NOT retryable (a retry may double-execute) -- the two properties that used to
    #: be the same thing. An attempt here waits for reconciliation.
    UNCERTAIN_OUTCOMES = frozenset({Outcome.UNKNOWN})

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    deployment = models.ForeignKey(
        Deployment, on_delete=models.CASCADE, related_name="dispatch_attempts"
    )
    finding = models.ForeignKey(
        Finding, on_delete=models.CASCADE, related_name="dispatch_attempts"
    )
    connector = models.CharField(max_length=64)
    # The binding this used, kept for provenance. SET_NULL so removing a binding
    # never erases the audit trail of what it dispatched.
    binding = models.ForeignKey(
        ConnectorBinding,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="attempts",
    )
    outcome = models.CharField(max_length=32, choices=Outcome.choices)
    trigger = models.CharField(max_length=32, choices=Trigger.choices)
    # Human-readable outcome line (the ConnectorResult detail, or why it was
    # skipped). Never a credential.
    detail = models.TextField(blank=True)
    # The id the external system handed back (Jira key, ServiceNow sys_id, ...),
    # for reconciliation. Blank when there is none.
    external_ref = models.CharField(max_length=255, blank=True, default="")
    # The durable identity of this operation, sent to the provider as an
    # idempotency key. Without one, reconciling an uncertain outcome means asking
    # "did you already do this?" with nothing to name the thing -- and a retry has
    # no way to be deduplicated by the provider rather than by us guessing.
    # Deterministic from (finding, connector), so the same operation retried is the
    # same operation, and a different finding is never mistaken for it.
    operation_id = models.CharField(max_length=64, blank=True, default="", db_index=True)
    # The policy epoch this was authorized under. A retry after the epoch moved is
    # being executed under an authority that no longer holds, and that is a
    # different decision from the one that was made.
    policy_epoch = models.CharField(max_length=64, blank=True, default="")
    # When an uncertain outcome was resolved against the provider, and how. Null
    # while it is still unresolved -- which is the state that blocks the retry.
    reconciled_at = models.DateTimeField(null=True, blank=True)
    reconciled_detail = models.TextField(blank=True)
    attempts = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["finding", "connector"], name="uq_dispatch_attempt_finding_connector"
            )
        ]
        indexes = [
            models.Index(fields=["deployment", "outcome"]),
            models.Index(fields=["finding", "connector"]),
        ]

    @property
    def is_terminal(self) -> bool:
        """Whether this attempt is done (accepted) — the idempotency guard: a
        terminal attempt is never re-pushed."""
        return self.outcome in self.TERMINAL_OUTCOMES

    @property
    def is_uncertain(self) -> bool:
        """Whether the provider may have committed this and nobody has checked."""
        return self.outcome in self.UNCERTAIN_OUTCOMES and self.reconciled_at is None

    @property
    def blocks_retry(self) -> bool:
        """Whether this attempt must NOT be pushed again as things stand.

        Two different reasons, and separating them is the point of this change: a
        terminal attempt was accepted, so re-pushing would duplicate a known
        ticket; an unresolved uncertain attempt MIGHT have been accepted, so
        re-pushing might duplicate one nobody can see. Before this, only the first
        blocked a retry, and the second was retried on every qualifying trigger.
        """
        return self.is_terminal or self.is_uncertain

    def __str__(self) -> str:
        return f"{self.connector} <- finding {self.finding_id}: {self.outcome}"
