"""Serializers for the assurance system-of-record API.

Read-heavy: the engine owns most finding fields, so the API exposes them
read-only and allows a human to change only the workflow fields (a finding's
status and owner). Secrets never appear here — the engine already redacts its
responses, and the API surfaces structured columns, not raw target material.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import (
    Asset,
    Deployment,
    Evidence,
    Finding,
    Provider,
    ProviderAssertion,
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


class FindingSerializer(serializers.ModelSerializer):
    evidence = EvidenceSerializer(many=True, read_only=True)
    evidence_class = serializers.CharField(read_only=True)
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    # The asset this finding concerns, once discovery has attached it (Phase 1.1).
    asset_uuid = serializers.UUIDField(source="asset.uuid", read_only=True, allow_null=True)
    asset_name = serializers.CharField(source="asset.name", read_only=True, allow_null=True)
    owner = _owner_field()

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
            "owner",
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
            "description",
            "finding_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
