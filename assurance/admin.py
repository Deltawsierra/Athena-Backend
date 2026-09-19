from django.contrib import admin

from .models import (
    Asset,
    ConnectorBinding,
    DataBoundary,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    Evidence,
    Finding,
    PostureBinding,
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
    list_display = ("name", "kind", "classification", "classification_source", "deployment")
    list_filter = ("kind", "classification", "classification_source")
    search_fields = ("name", "identifier")

    def save_model(self, request, obj, form, change):
        # An operator editing the classification in the admin is a human decision:
        # stamp its provenance so a later machine re-derive preserves it rather than
        # overwriting it (see Asset.ClassificationSource / assets._get_or_refresh).
        if change and "classification" in getattr(form, "changed_data", ()):
            obj.classification_source = Asset.ClassificationSource.HUMAN
        super().save_model(request, obj, form, change)


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


# ---------------------------------------------------------------------------
# Commercial spine — connector / posture bindings and dispatch
# ---------------------------------------------------------------------------
# The encrypted credential column is NEVER shown or editable in the admin: a
# secret is set through the admin-gated API (write-only, encrypted at rest). The
# admin shows only whether one is on file and whether the binding is operational.


class _CredentialBindingAdmin(admin.ModelAdmin):
    # The ciphertext column is deliberately excluded from the form so a plaintext
    # secret can never be pasted into it here; credentials are set via the API.
    exclude = ("secret_ciphertext",)
    readonly_fields = ("uuid", "has_secret", "operational", "created_at", "updated_at")

    @admin.display(boolean=True, description="Credential on file")
    def has_secret(self, obj):
        return obj.has_secret

    @admin.display(boolean=True, description="Operational")
    def operational(self, obj):
        return obj.is_operational()


@admin.register(ConnectorBinding)
class ConnectorBindingAdmin(_CredentialBindingAdmin):
    list_display = ("connector", "deployment", "enabled", "has_secret", "operational", "updated_at")
    list_filter = ("connector", "enabled")
    search_fields = ("deployment__name", "connector")


@admin.register(PostureBinding)
class PostureBindingAdmin(_CredentialBindingAdmin):
    list_display = ("domain", "deployment", "enabled", "has_secret", "operational", "updated_at")
    list_filter = ("domain", "enabled")
    search_fields = ("deployment__name", "domain")


@admin.register(DispatchPolicy)
class DispatchPolicyAdmin(admin.ModelAdmin):
    list_display = ("deployment", "enabled", "min_severity", "on_blocking_decision", "updated_at")
    list_filter = ("enabled", "min_severity", "on_blocking_decision")
    search_fields = ("deployment__name",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(DispatchAttempt)
class DispatchAttemptAdmin(admin.ModelAdmin):
    # An audit trail: written only by the dispatcher, never hand-edited.
    list_display = ("connector", "finding", "deployment", "outcome", "trigger", "attempts", "updated_at")
    list_filter = ("outcome", "trigger", "connector")
    search_fields = ("deployment__name", "finding__title", "connector", "external_ref")
    readonly_fields = (
        "uuid", "deployment", "finding", "connector", "binding", "outcome",
        "trigger", "detail", "external_ref", "attempts", "created_at", "updated_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
