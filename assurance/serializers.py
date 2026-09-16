"""Serializers for the assurance system-of-record API.

Read-heavy: the engine owns most finding fields, so the API exposes them
read-only and allows a human to change only the workflow fields (a finding's
status and owner). Secrets never appear here — the engine already redacts its
responses, and the API surfaces structured columns, not raw target material.
"""

from __future__ import annotations

from rest_framework import serializers

from .models import Asset, Deployment, Evidence, Finding, Provider, Unknown


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
    class Meta:
        model = Asset
        fields = [
            "uuid",
            "kind",
            "name",
            "identifier",
            "classification",
            "provider",
            "metadata",
            "first_seen",
            "last_seen",
        ]
        read_only_fields = fields


class ProviderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Provider
        fields = ["uuid", "name", "kind", "region", "notes", "evidence_class"]
        read_only_fields = fields


class UnknownSerializer(serializers.ModelSerializer):
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    impact_label = serializers.CharField(
        source="get_deployment_impact_display", read_only=True
    )
    deployment_uuid = serializers.UUIDField(source="deployment.uuid", read_only=True)
    finding_uuid = serializers.UUIDField(source="finding.uuid", read_only=True, allow_null=True)

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
