"""Read-focused API over the assurance system of record.

Findings, deployments, assets, and providers are exposed for the dashboard to
query. Findings are read-only except for the human workflow fields (status,
owner, business_impact) — the engine owns the rest and ingestion keeps it
current. Access follows the project's existing per-user ownership model: a caller
sees the deployments and findings tied to scans they can see (admins see all),
matching how ``pentest`` already scopes visibility.
"""

from __future__ import annotations

import uuid as uuidlib

from django.db.models import Count
from rest_framework import mixins, permissions, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from .decision import recompute_decision
from .models import Asset, Deployment, Finding, Provider, ProviderAssertion, Unknown
from .serializers import (
    AssetSerializer,
    DeploymentSerializer,
    FindingSerializer,
    ProviderAssertionSerializer,
    ProviderSerializer,
    UnknownSerializer,
)


def _is_privileged(user) -> bool:
    """Who may *read* the whole assurance graph: admins and analysts. Other
    authenticated users see only their own (the read model is intentionally
    broad; writes are separately restricted to admins by ``_require_admin``)."""
    return bool(
        getattr(user, "is_superuser", False)
        or getattr(user, "is_admin", False)
        or getattr(user, "is_analyst", False)
    )


def _is_admin(user) -> bool:
    """Who may *write* to the assurance system of record. ``is_admin`` already
    includes superusers; analysts and below may read but not mutate."""
    return bool(getattr(user, "is_superuser", False) or getattr(user, "is_admin", False))


def _require_admin(request) -> None:
    """Gate a mutating action to admins. A write changes the shared system of
    record (a decision, a disposition), so it is admin-only even though reads are
    open — a non-admin gets a clean 403, not a silent success."""
    if not _is_admin(request.user):
        raise PermissionDenied("Changing the assurance record requires an admin role.")


def _valid_uuid(value: str) -> str | None:
    """A well-formed UUID string, or None. A malformed ``?deployment=`` filter
    must not reach the ORM as a raw string — that raises a Django ValidationError
    DRF does not catch, surfacing as a 500 instead of an empty result set."""
    try:
        return str(uuidlib.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


class DeploymentViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = DeploymentSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"

    def get_queryset(self):
        qs = Deployment.objects.all().annotate(finding_count=Count("findings"))
        user = self.request.user
        if _is_privileged(user):
            return qs
        # Own deployments, or deployments whose findings came from the user's scans.
        return qs.filter(owner=user).distinct()

    @action(detail=True, methods=["post"])
    def recompute(self, request, uuid=None):
        """Recompute the deployment's six-state decision from its live findings.
        Accepts an optional ``paused`` flag (the operator failsafe state), which
        overrides to "Deployment paused". Admin-only: it mutates the record."""
        _require_admin(request)
        deployment = self.get_object()
        paused = bool(request.data.get("paused", False))
        decision = recompute_decision(deployment, paused=paused)
        return Response({"decision": decision, "decision_label": deployment.get_decision_display()})


class FindingViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,  # PATCH: status / owner / business_impact only
    viewsets.GenericViewSet,
):
    serializer_class = FindingSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "patch", "head", "options"]

    def update(self, request, *args, **kwargs):
        # PATCH (status/owner/business_impact) mutates the record → admin-only.
        _require_admin(request)
        return super().update(request, *args, **kwargs)

    def _scoped_findings(self):
        """Every finding the caller may see, BEFORE the severity/status/deployment
        query filters. The change-intelligence boundary (a deployment's latest
        scan) is a fact about the deployment, so it must be computed over the
        unfiltered set — a ``?status=open`` view must not redefine "latest scan"."""
        qs = Finding.objects.all()
        user = self.request.user
        if _is_privileged(user):
            return qs
        return (qs.filter(scan__user=user) | qs.filter(deployment__owner=user)).distinct()

    def get_serializer_context(self):
        """Supply the change-intelligence inputs once per request: the latest-scan
        boundary per deployment (one aggregate query) and a single ``now``, so the
        serializer never issues a query per finding."""
        from django.utils import timezone

        from .change import latest_seen_by_deployment

        ctx = super().get_serializer_context()
        ctx["latest_seen"] = latest_seen_by_deployment(self._scoped_findings())
        ctx["now"] = timezone.now()
        return ctx

    def get_queryset(self):
        qs = self._scoped_findings().select_related("deployment").prefetch_related("evidence")
        severity = self.request.query_params.get("severity")
        if severity:
            qs = qs.filter(severity=severity)
        status_q = self.request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            # A malformed uuid matches nothing, rather than raising a 500.
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        return qs


class AssetViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = AssetSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"

    def get_queryset(self):
        qs = (
            Asset.objects.select_related("deployment", "provider")
            .annotate(finding_count=Count("findings"))
            .order_by("deployment_id", "kind", "name")
        )
        user = self.request.user
        if not _is_privileged(user):
            qs = qs.filter(deployment__owner=user).distinct()
        kind = self.request.query_params.get("kind")
        if kind:
            qs = qs.filter(kind=kind)
        classification = self.request.query_params.get("classification")
        if classification:
            qs = qs.filter(classification=classification)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            # A malformed uuid matches nothing, rather than raising a 500.
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        return qs


class ProviderViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Providers are a global registry (an Asset points at one), so reads are
    open to any authenticated operator. An admin may declare a provider and edit
    its assurance profile; a non-admin may not (open reads, admin-only writes)."""

    serializer_class = ProviderSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "post", "patch", "head", "options"]
    queryset = Provider.objects.all().prefetch_related("assertions")

    def create(self, request, *args, **kwargs):
        _require_admin(request)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        _require_admin(request)
        return super().update(request, *args, **kwargs)


class ProviderAssertionViewSet(viewsets.ModelViewSet):
    """The graded facts of a provider's assurance profile (Phase 1.5). Reads are
    open; creating/editing/deleting an assertion is admin-only and records who
    made the change."""

    serializer_class = ProviderAssertionSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    def get_queryset(self):
        qs = ProviderAssertion.objects.select_related("provider", "updated_by").all()
        provider = self.request.query_params.get("provider")
        if provider:
            valid = _valid_uuid(provider)
            qs = qs.filter(provider__uuid=valid) if valid else qs.none()
        field = self.request.query_params.get("field")
        if field:
            qs = qs.filter(field=field)
        return qs

    def create(self, request, *args, **kwargs):
        _require_admin(request)
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        _require_admin(request)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        _require_admin(request)
        return super().destroy(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)


class UnknownViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,  # PATCH: disposition fields only (status/owner/notes/review_by/impact)
    viewsets.GenericViewSet,
):
    serializer_class = UnknownSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    http_method_names = ["get", "patch", "head", "options"]

    def update(self, request, *args, **kwargs):
        # PATCH (disposition fields) mutates the record → admin-only.
        _require_admin(request)
        return super().update(request, *args, **kwargs)

    def get_queryset(self):
        qs = Unknown.objects.all().select_related("deployment", "finding")
        user = self.request.user
        if not _is_privileged(user):
            # Unknowns on a deployment the user owns, or derived from a finding on
            # a scan they launched. Mirrors the finding scoping.
            qs = qs.filter(deployment__owner=user) | qs.filter(finding__scan__user=user)
            qs = qs.distinct()
        status_q = self.request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)
        impact = self.request.query_params.get("impact")
        if impact:
            qs = qs.filter(deployment_impact=impact)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            # A malformed uuid matches nothing, rather than raising a 500.
            valid = _valid_uuid(deployment)
            qs = qs.filter(deployment__uuid=valid) if valid else qs.none()
        return qs
