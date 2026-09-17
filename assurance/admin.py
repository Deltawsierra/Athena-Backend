from django.contrib import admin

from .models import (
    Asset,
    DataBoundary,
    Deployment,
    Evidence,
    Finding,
    Provider,
    ProviderAssertion,
    RemediationEvent,
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


class RemediationEventInline(admin.TabularInline):
    model = RemediationEvent
    extra = 0
    # The trail is written only through assurance.remediation, never hand-edited.
    readonly_fields = ("from_state", "to_state", "actor", "note", "created_at")

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Deployment)
class DeploymentAdmin(admin.ModelAdmin):
    list_display = ("name", "environment", "decision", "updated_at")
    list_filter = ("environment", "decision")
    search_fields = ("name",)


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "severity",
        "status",
        "remediation_state",
        "assignee",
        "deployment",
        "retest_required",
        "last_seen",
    )
    list_filter = ("severity", "status", "remediation_state", "retest_required")
    search_fields = ("title", "finding_type", "location")
    inlines = [EvidenceInline, RemediationEventInline]


@admin.register(RemediationEvent)
class RemediationEventAdmin(admin.ModelAdmin):
    list_display = ("finding", "from_state", "to_state", "actor", "created_at")
    list_filter = ("to_state", "from_state")
    search_fields = ("finding__title", "note")
    readonly_fields = ("finding", "from_state", "to_state", "actor", "note", "created_at")


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
