from django.contrib import admin

from .models import Asset, Deployment, Evidence, Finding, Provider, Unknown


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


@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "region", "evidence_class")
    list_filter = ("kind", "evidence_class")
    search_fields = ("name",)


@admin.register(Unknown)
class UnknownAdmin(admin.ModelAdmin):
    list_display = ("question", "deployment", "deployment_impact", "status", "source", "review_by")
    list_filter = ("status", "deployment_impact", "source")
    search_fields = ("question", "why_it_matters")
