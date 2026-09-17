from django.contrib import admin

from .models import (
    Asset,
    DataBoundary,
    Deployment,
    Evidence,
    Finding,
    Provider,
    ProviderAssertion,
    Unknown,
)


@admin.register(DataBoundary)
class DataBoundaryAdmin(admin.ModelAdmin):
    list_display = ("deployment", "training_allowed", "third_party_sharing_allowed", "updated_at")
    list_filter = ("training_allowed", "third_party_sharing_allowed")
    search_fields = ("deployment__name",)


class EvidenceInline(admin.TabularInline):
    model = Evidence
    extra = 0
    readonly_fields = ("classification", "source", "content_hash", "created_at")


@admin.register(Deployment)
class DeploymentAdmin(admin.ModelAdmin):
    list_display = ("name", "environment", "decision", "updated_at")
    list_filter = ("environment", "decision")
    search_fields = ("name",)


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "status", "deployment", "retest_required", "last_seen")
    list_filter = ("severity", "status", "retest_required")
    search_fields = ("title", "finding_type", "location")
    inlines = [EvidenceInline]


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "classification", "deployment")
    list_filter = ("kind", "classification")
    search_fields = ("name", "identifier")


class ProviderAssertionInline(admin.TabularInline):
    model = ProviderAssertion
    extra = 0


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "region", "evidence_class")
    list_filter = ("kind", "evidence_class")
    search_fields = ("name",)
    inlines = [ProviderAssertionInline]


@admin.register(ProviderAssertion)
class ProviderAssertionAdmin(admin.ModelAdmin):
    list_display = ("provider", "field", "value", "evidence_class", "source", "updated_at")
    list_filter = ("field", "evidence_class", "source")
    search_fields = ("provider__name", "value")


@admin.register(Unknown)
class UnknownAdmin(admin.ModelAdmin):
    list_display = ("question", "deployment", "deployment_impact", "status", "source", "review_by")
    list_filter = ("status", "deployment_impact", "source")
    search_fields = ("question", "why_it_matters")
