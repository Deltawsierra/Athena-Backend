from django.contrib import admin
from django.db import transaction

from .decision import refresh_stored_decisions
from .revision import in_force_of, logged_head
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


class _RefreshesTheStoredDecision:
    """A change made here to a decision input refreshes the stored decision, in the
    admin's own transaction.

    The admin wrote findings, assets and a deployment's own inputs
    (``evidence_incomplete``, ``last_complete_scan_at``) and recomputed nothing, so
    an admin who re-opened a critical finding left the receipt reading READY while
    decision-support, computing live, said NOT_RECOMMENDED. The change form and the
    delete view each run in a transaction, and the refresh runs inside it -- after
    the row AND its inlines are saved, since an evidence row edited inline moves its
    finding's evidence class. The after-commit backstop in :mod:`assurance.signals`
    would bring the decision current as well, but only once this transaction had
    committed, leaving a moment in which the new input stood beside the old
    decision. Here there is none.
    """

    #: The lookup from a row of this admin's model to its deployment's pk.
    decision_deployment_lookup = "deployment"

    def _deployments_of(self, queryset) -> set:
        return set(queryset.values_list(self.decision_deployment_lookup, flat=True))

    def save_model(self, request, obj, form, change):
        rows = type(obj)._default_manager.filter(pk=obj.pk)
        # The deployment the row belonged to BEFORE this save as well as after it:
        # an admin can move a finding or an asset to another deployment, and that
        # moves both decisions.
        before = self._deployments_of(rows) if change else set()
        super().save_model(request, obj, form, change)
        # On the request, not on this admin: one ModelAdmin serves every request.
        request._assurance_decision_deployments = before | self._deployments_of(rows)

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        refresh_stored_decisions(getattr(request, "_assurance_decision_deployments", ()))

    def delete_model(self, request, obj):
        deployments = self._deployments_of(type(obj)._default_manager.filter(pk=obj.pk))
        super().delete_model(request, obj)
        refresh_stored_decisions(deployments)

    def delete_queryset(self, request, queryset):
        # The changelist's bulk delete is not wrapped in a transaction by the admin
        # the way the change form is, so this one opens its own.
        with transaction.atomic(using=queryset.db):
            deployments = self._deployments_of(queryset)
            super().delete_queryset(request, queryset)
            refresh_stored_decisions(deployments)


@admin.register(Deployment)
class DeploymentAdmin(_RefreshesTheStoredDecision, admin.ModelAdmin):
    list_display = ("name", "environment", "decision_in_force", "updated_at")
    # Over the stored column. A row behind its transition log (legacy data, which
    # the post_migrate repair and the first published read bring level) is filed
    # under its stale value until then; the column beside it says what is in force.
    list_filter = ("environment", "decision")
    search_fields = ("name",)
    # Written only through `assurance.revision.accept_transition`. Editable here,
    # an admin could set a READY no rule computed -- and one `current_decision`
    # would trust, the keyring stamp untouched. Read-only in the form is not what
    # keeps a save from writing them back, though: `save_model` saves the whole
    # instance, and an instance loaded before a recompute holds the decision from
    # before it. `Deployment.save` leaves these columns out of every UPDATE.
    readonly_fields = (
        "decision",
        "decision_revision",
        "decision_keyring",
        "decision_in_force",
        "revision_in_force",
    )
    # The decision cannot be typed in here, and it must not be left behind either:
    # `evidence_incomplete` and `last_complete_scan_at` are inputs to it.
    decision_deployment_lookup = "pk"

    def get_queryset(self, request):
        # The head of each row's transition log, in the list's one query -- and in
        # the change form's, which reads its row through this queryset.
        return super().get_queryset(request).annotate(**logged_head())

    def get_fields(self, request, obj=None):
        # The change form shows the decision IN FORCE and its revision, not the
        # stored columns: on a row behind its transition log those hold the stale
        # READY beneath a logged pause, on the page an operator opens to check the
        # pause. Still read-only above, which keeps them off the form.
        stored = {"decision", "decision_revision"}
        return [name for name in super().get_fields(request, obj) if name not in stored]

    @staticmethod
    def _in_force(obj):
        return in_force_of(
            obj.decision,
            obj.decision_revision,
            getattr(obj, "logged_revision", None),
            getattr(obj, "logged_decision", None),
        )

    @admin.display(description="decision", ordering="decision")
    def decision_in_force(self, obj):
        """The decision in force, as every published read has it: a row behind its
        transition log shows what the log records -- a logged pause as the pause,
        not the READY the stale row holds. A read: it repairs nothing."""
        decision, _revision = self._in_force(obj)
        return Deployment.Decision(decision).label if decision else "-"

    @admin.display(description="decision revision")
    def revision_in_force(self, obj):
        """The revision of the decision in force: the log's, for a row behind it."""
        _decision, revision = self._in_force(obj)
        return revision


@admin.register(Finding)
class FindingAdmin(_RefreshesTheStoredDecision, admin.ModelAdmin):
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
class AssetAdmin(_RefreshesTheStoredDecision, admin.ModelAdmin):
    list_display = ("name", "kind", "classification", "classification_source", "deployment")
    list_filter = ("kind", "classification", "classification_source")
    search_fields = ("name", "identifier")

    def save_model(self, request, obj, form, change):
        # An operator editing the classification in the admin is a human decision:
        # stamp its provenance so a later machine re-derive preserves it rather than
        # overwriting it (see Asset.ClassificationSource / assets._get_or_refresh).
        if change and "classification" in getattr(form, "changed_data", ()):
            obj.classification_source = Asset.ClassificationSource.HUMAN
        # And a rename is a person's too: marked, so no settle or re-declaration
        # of the key puts a machine name back over it (see assets.NAMED_BY_HAND).
        if change and "name" in getattr(form, "changed_data", ()):
            from .assets import NAMED_BY_HAND

            obj.metadata = {**(obj.metadata if isinstance(obj.metadata, dict) else {}), NAMED_BY_HAND: True}
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
