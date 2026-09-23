"""Serializers for the assurance system-of-record API.

Read-heavy: the engine owns most finding fields, so the API exposes them
read-only and allows a human to change only the workflow fields (a finding's
status and owner). Secrets never appear here — the engine already redacts its
responses, and the API surfaces structured columns, not raw target material.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .change import CHANGE_LABELS, age_days, change_status, is_stale
from .receipt import finding_receipt
from .models import (
    Asset,
    AssuranceClaim,
    ClaimEvent,
    DataBoundary,
    DeclaredComponent,
    Deployment,
    Evidence,
    Finding,
    Provider,
    ProviderAssertion,
    RemediationEvent,
    RetestRequirement,
    Unknown,
    evidence_strength,
)

User = get_user_model()


def _owner_field() -> serializers.SlugRelatedField:
    """Owner as a **username**, read and write, rather than the raw user id a
    ModelSerializer would emit — a bare integer in the owner column is
    meaningless to a reader and to the dashboard."""
    return serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.all(),
        allow_null=True,
        required=False,
    )


class EvidenceSerializer(serializers.ModelSerializer):
    classification_label = serializers.CharField(
        source="get_classification_display", read_only=True
    )

    class Meta:
        model = Evidence
        fields = [
            "uuid",
            "classification",
            "classification_label",
            "summary",
            "source",
            "content_hash",
            "created_at",
        ]
        read_only_fields = fields


class RemediationEventSerializer(serializers.ModelSerializer):
    """One attributed step in a finding's remediation workflow (Phase 2.3),
    read-only — events are written only through ``assurance.remediation`` so every
    move is validated and attributed."""

    from_state_label = serializers.CharField(source="get_from_state_display", read_only=True)
    to_state_label = serializers.CharField(source="get_to_state_display", read_only=True)
    actor = serializers.CharField(source="actor.username", read_only=True, allow_null=True)

    class Meta:
        model = RemediationEvent
        fields = [
            "uuid",
            "from_state",
            "from_state_label",
            "to_state",
            "to_state_label",
            "actor",
            "note",
            "created_at",
        ]
        read_only_fields = fields


class FindingSerializer(serializers.ModelSerializer):
    evidence = EvidenceSerializer(many=True, read_only=True)
    evidence_class = serializers.CharField(read_only=True)
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    # The asset this finding concerns, once discovery has attached it (Phase 1.1).
    asset_uuid = serializers.UUIDField(source="asset.uuid", read_only=True, allow_null=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True, allow_null=True)
    owner = _owner_field()
    # Remediation workflow (Phase 2.3): the human process axis, read-only here.
    # `remediation_state` moves only through the admin-gated, attributed transition
    # action (never a raw PATCH), so the state machine is always enforced; likewise
    # `assignee` is set through the assign action. Both are distinct from the
    # security disposition (`status`), which alone says whether the risk is live.
    remediation_state_label = serializers.CharField(
        source="get_remediation_state_display", read_only=True
    )
    assignee = serializers.CharField(source="assignee.username", read_only=True, allow_null=True)
    # Change intelligence + evidence expiration (spine, EXPOSE). Derived from the
    # existing first_seen/last_seen against the deployment's latest scan, which the
    # viewset supplies via serializer context ("latest_seen" / "now") in one query.
    change_status = serializers.SerializerMethodField()
    change_label = serializers.SerializerMethodField()
    age_days = serializers.SerializerMethodField()
    stale = serializers.SerializerMethodField()
    # Assurance receipt (spine, EXPOSE): a recomputable digest binding this finding
    # to its evidence hashes. Integrity/provenance, not proof the conclusion is
    # true — the evidence class carries how strongly it is known.
    receipt = serializers.SerializerMethodField()
    # What this status must not be read as, where the status has a wrong reading
    # worth naming. Served from the model's one table so the API and the dashboard
    # cannot each invent their own caveat -- a CONTAINED finding that a report
    # renders as "being fixed", or an INVALIDATED one it renders as an incident, is
    # the whole reason these states were added.
    status_must_not_imply = serializers.SerializerMethodField()
    # The disposition's own words. Without it a consumer has only the slug, and
    # the only way to render "contained" as anything a reader understands is to
    # write a label of its own -- which is how two surfaces end up disagreeing
    # about a state that exists *because* its wrong reading is easy. The caveat
    # beside it is served from the same table for the same reason.
    status_label = serializers.CharField(source="get_status_display", read_only=True)

    def get_status_must_not_imply(self, obj) -> str | None:
        return Finding.MUST_NOT_IMPLY.get(obj.status)

    class Meta:
        model = Finding
        fields = [
            "uuid",
            "deployment_uuid",
            "finding_type",
            "title",
            "severity",
            "confidence",
            "cvss_score",
            "cvss_vector",
            "status",
            "status_label",
            "status_must_not_imply",
            "owner",
            "assignee",
            "remediation_state",
            "remediation_state_label",
            "impact",
            "business_impact",
            "recommendation",
            "control_mapping",
            "location",
            "retest_required",
            "evidence_class",
            "evidence",
            "asset_uuid",
            "asset_name",
            "change_status",
            "change_label",
            "age_days",
            "stale",
            "receipt",
            "first_seen",
            "last_seen",
        ]
        # Only the human workflow fields are writable; everything else is the
        # engine's truth and is refreshed by ingestion, so it stays read-only.
        read_only_fields = [
            f
            for f in fields
            if f not in ("status", "owner", "business_impact")
        ]

    def _latest_seen(self, obj):
        return (self.context.get("latest_seen") or {}).get(obj.deployment_id)

    def get_change_status(self, obj) -> str:
        return change_status(obj, self._latest_seen(obj))

    def get_change_label(self, obj) -> str:
        return CHANGE_LABELS.get(self.get_change_status(obj), "")

    def get_age_days(self, obj):
        return age_days(obj, self.context.get("now"))

    def get_stale(self, obj) -> bool:
        return is_stale(obj, self.context.get("now"))

    def get_receipt(self, obj) -> dict:
        return finding_receipt(obj)


class AssetSerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    classification_label = serializers.CharField(
        source="get_classification_display", read_only=True
    )
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    # The provider this asset resolves to, by uuid — the stable join key the
    # dashboard uses to link an asset to that provider's full assurance profile.
    # `provider` (the raw pk) is meaningless across origins; the name is not a
    # key. The uuid is how the asset graph draws its edge to the provider node.
    provider_uuid = serializers.UUIDField(source="provider.uuid", read_only=True, allow_null=True)
    provider_name = serializers.CharField(source="provider.name", read_only=True, allow_null=True)
    finding_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Asset
        fields = [
            "uuid",
            "deployment_uuid",
            "kind",
            "kind_label",
            "name",
            "identifier",
            "classification",
            "classification_label",
            "provider",
            "provider_uuid",
            "provider_name",
            "finding_count",
            "metadata",
            "first_seen",
            "last_seen",
        ]
        read_only_fields = fields


class ProviderAssertionSerializer(serializers.ModelSerializer):
    field_label = serializers.CharField(source="get_field_display", read_only=True)
    evidence_class_label = serializers.CharField(
        source="get_evidence_class_display", read_only=True
    )
    source_label = serializers.CharField(source="get_source_display", read_only=True)
    provider = serializers.SlugRelatedField(
        slug_field="uuid", queryset=Provider.objects.all()
    )
    provider_name = serializers.CharField(source="provider.name", read_only=True)
    updated_by = serializers.CharField(source="updated_by.username", read_only=True, allow_null=True)

    class Meta:
        model = ProviderAssertion
        fields = [
            "uuid",
            "provider",
            "provider_name",
            "field",
            "field_label",
            "value",
            "evidence_class",
            "evidence_class_label",
            "source",
            "source_label",
            "notes",
            "updated_by",
            "updated_at",
        ]
        read_only_fields = ["uuid", "provider_name", "updated_by", "updated_at"]

    def validate(self, attrs):
        """One assertion per field per provider — the profile holds a single
        value for each fact, updated in place rather than duplicated."""
        provider = attrs.get("provider") or getattr(self.instance, "provider", None)
        field = attrs.get("field") or getattr(self.instance, "field", None)
        if provider is not None and field is not None:
            qs = ProviderAssertion.objects.filter(provider=provider, field=field)
            if self.instance is not None:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise serializers.ValidationError(
                    {"field": f"This provider already has a '{field}' assertion; edit it instead."}
                )
        return attrs


class ProviderProfileAssertionSerializer(serializers.ModelSerializer):
    """The read-only view of an assertion as it appears *inside* a provider's
    profile (its provider is implied by the parent)."""

    field_label = serializers.CharField(source="get_field_display", read_only=True)
    evidence_class_label = serializers.CharField(
        source="get_evidence_class_display", read_only=True
    )
    source_label = serializers.CharField(source="get_source_display", read_only=True)

    class Meta:
        model = ProviderAssertion
        fields = [
            "uuid",
            "field",
            "field_label",
            "value",
            "evidence_class",
            "evidence_class_label",
            "source",
            "source_label",
            "notes",
            "updated_at",
        ]
        read_only_fields = fields


class ProviderSerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    assertions = ProviderProfileAssertionSerializer(many=True, read_only=True)
    # The honest headline for the whole profile: how many facts are recorded and
    # the *weakest* evidence among them, so a profile is never read as stronger
    # than its softest claim.
    profile = serializers.SerializerMethodField()

    class Meta:
        model = Provider
        fields = [
            "uuid",
            "name",
            "kind",
            "kind_label",
            "region",
            "notes",
            "evidence_class",
            "assertions",
            "profile",
        ]
        # Identity and the declared fields are admin-writable (enforced in the
        # view); uuid and the derived views are read-only.
        read_only_fields = ["uuid", "kind_label", "assertions", "profile"]

    def get_profile(self, obj) -> dict:
        classes = [a.evidence_class for a in obj.assertions.all()]
        weakest = max(classes, key=evidence_strength) if classes else None
        return {"declared_fields": len(classes), "weakest_evidence": weakest}


class UnknownSerializer(serializers.ModelSerializer):
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    impact_label = serializers.CharField(
        source="get_deployment_impact_display", read_only=True
    )
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    finding_uuid = serializers.UUIDField(source="finding.uuid", read_only=True, allow_null=True)
    owner = _owner_field()

    class Meta:
        model = Unknown
        fields = [
            "uuid",
            "deployment_uuid",
            "finding_uuid",
            "subject",
            "question",
            "why_it_matters",
            "evidence_needed",
            "deployment_impact",
            "impact_label",
            "status",
            "status_label",
            "source",
            "owner",
            "notes",
            "review_by",
            "first_seen",
            "last_seen",
        ]
        # A derived Unknown's substance is machine-owned and refreshed on
        # re-derive; a human works only the disposition fields.
        read_only_fields = [
            f
            for f in fields
            if f not in ("status", "owner", "notes", "review_by", "deployment_impact")
        ]


class DataBoundarySerializer(serializers.ModelSerializer):
    """The approved data boundary a human declares (Phase 1.4). Write-only shape:
    the assessment (approved-vs-actual) is computed and returned by the view, not
    stored here.

    Every field is optional (each maps to a model field with a default), so the
    view can drive both a true-replace PUT (it fills the fields the body omits from
    the model defaults) and a merge PATCH (``partial=True`` skips the omitted
    fields). The serializer only validates and shapes what is supplied; which
    omitted-field semantics apply is the view's decision."""

    class Meta:
        model = DataBoundary
        fields = ["allowed_regions", "training_allowed", "third_party_sharing_allowed", "notes"]

    def validate_allowed_regions(self, value):
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
            raise serializers.ValidationError("allowed_regions must be a list of strings.")
        # Drop blanks and dedupe while preserving order.
        seen: list[str] = []
        for v in value:
            v = v.strip()
            if v and v not in seen:
                seen.append(v)
        return seen


class DeclaredComponentSerializer(serializers.ModelSerializer):
    """One component the customer declares their AI system is built from (SPINE
    Stage 3). The write shape is the declaration; ``uuid`` and the kind label are
    read-only for the dashboard."""

    kind_label = serializers.CharField(source="get_kind_display", read_only=True)

    class Meta:
        model = DeclaredComponent
        fields = ["uuid", "kind", "kind_label", "name", "identifier", "provider_name", "note"]
        read_only_fields = ["uuid", "kind_label"]

    def validate_name(self, value):
        value = (value or "").strip()
        if not value:
            raise serializers.ValidationError("A declared component needs a name.")
        return value


class ClaimEventSerializer(serializers.ModelSerializer):
    """One attributed step in an assurance claim's lifecycle (SPINE), read-only —
    events are written only through ``assurance.claims`` (a derive or an attributed
    transition), so every move is validated and attributed."""

    from_status_label = serializers.CharField(source="get_from_status_display", read_only=True)
    to_status_label = serializers.CharField(source="get_to_status_display", read_only=True)
    actor = serializers.CharField(source="actor.username", read_only=True, allow_null=True)

    class Meta:
        model = ClaimEvent
        fields = [
            "uuid",
            "from_status",
            "from_status_label",
            "to_status",
            "to_status_label",
            "actor",
            "note",
            "created_at",
        ]
        read_only_fields = fields


class RetestRequirementSerializer(serializers.ModelSerializer):
    """An open/closed retest obligation on a claim (SPINE Phase 2), read-only —
    obligations are written only through ``assurance.invalidation`` (a change opens
    one) and ``assurance.claims.derive_claims`` (a rebinding re-derivation resolves
    one), so every one is machine-attributed and never hand-edited into a dishonest
    state. Exposes uuids (never pks), the actor's username (null = the machine), and
    the timestamps — mirroring ``ClaimEventSerializer``."""

    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    claim_uuid = serializers.UUIDField(source="claim.uuid", read_only=True)
    claim_type = serializers.CharField(source="claim.claim_type", read_only=True)
    claim_type_label = serializers.CharField(
        source="claim.get_claim_type_display", read_only=True
    )
    resolving_claim_uuid = serializers.UUIDField(
        source="resolving_claim.uuid", read_only=True, allow_null=True
    )
    actor = serializers.CharField(source="actor.username", read_only=True, allow_null=True)
    is_open = serializers.BooleanField(read_only=True)

    class Meta:
        model = RetestRequirement
        fields = [
            "uuid",
            "deployment_uuid",
            "claim_uuid",
            "claim_type",
            "claim_type_label",
            "resolving_claim_uuid",
            "reason",
            "triggering_system_fingerprint",
            "actor",
            "is_open",
            "opened_at",
            "resolved_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class AssuranceClaimSerializer(serializers.ModelSerializer):
    """A version-bound, falsifiable assurance claim (SPINE), read-only. Every field
    is machine-derived or moved through the attributed transition action; the API
    never lets a claim be hand-edited into a dishonest state. Human-readable labels
    ride alongside the raw enums, and ``is_stale`` is surfaced so a consumer sees an
    expired claim as expired."""

    claim_type_label = serializers.CharField(source="get_claim_type_display", read_only=True)
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    evidence_class_label = serializers.CharField(
        source="get_evidence_class_display", read_only=True
    )
    assessment_label = serializers.SerializerMethodField()
    environment_label = serializers.CharField(source="get_environment_display", read_only=True)
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    asset_uuid = serializers.UUIDField(source="asset.uuid", read_only=True, allow_null=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True, allow_null=True)
    human_owner = serializers.CharField(
        source="human_owner.username", read_only=True, allow_null=True
    )
    superseded_by = serializers.UUIDField(
        source="superseded_by.uuid", read_only=True, allow_null=True
    )
    is_stale = serializers.BooleanField(read_only=True)

    class Meta:
        model = AssuranceClaim
        fields = [
            "uuid",
            "deployment_uuid",
            "asset_uuid",
            "asset_name",
            "claim_type",
            "claim_type_label",
            "statement",
            "fingerprint",
            "system_fingerprint",
            "policy_version",
            "environment",
            "environment_label",
            "status",
            "status_label",
            "evidence_class",
            "evidence_class_label",
            "confidence",
            "vendor_asserted",
            "assessment",
            "assessment_label",
            "supporting_summary",
            "contradicting_summary",
            "invalidation_conditions",
            "superseded_by",
            "human_owner",
            "receipt_digest",
            "is_stale",
            "valid_from",
            "valid_to",
            "verified_at",
            "expiration",
            "first_seen",
            "last_seen",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_assessment_label(self, obj) -> str | None:
        # None-safe: an unassessed deployment has no decision, and an absent
        # decision is never read as "ready".
        return obj.get_assessment_display() if obj.assessment else None


class DeploymentSerializer(serializers.ModelSerializer):
    decision_label = serializers.CharField(source="get_decision_display", read_only=True)
    finding_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Deployment
        fields = [
            "uuid",
            "name",
            "environment",
            "decision",
            "decision_label",
            # The monotonic revision this decision was written at. Served because
            # the revision fence was unreachable over HTTP: a consumer could read a
            # decision and had no way to tell a fresh one from one superseded
            # between its read and its action.
            "decision_revision",
            "description",
            "finding_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
