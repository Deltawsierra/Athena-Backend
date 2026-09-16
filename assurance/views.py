"""Read-focused API over the assurance system of record.

Findings, deployments, assets, and providers are exposed for the dashboard to
query. Findings are read-only except for the human workflow fields (status,
owner, business_impact) — the engine owns the rest and ingestion keeps it
current. Access follows the project's existing per-user ownership model: a caller
sees the deployments and findings tied to scans they can see (admins see all),
matching how ``pentest`` already scopes visibility.
"""

from __future__ import annotations

from django.db.models import Count
from rest_framework import mixins, permissions, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .decision import recompute_decision
from .models import Asset, Deployment, Finding, Provider
from .serializers import (
    AssetSerializer,
    DeploymentSerializer,
    FindingSerializer,
    ProviderSerializer,
)


def _is_privileged(user) -> bool:
    """Admins/analysts see everything; other authenticated users see only their
    own. Mirrors pentest.views.scans_visible_to rather than inventing a rule."""
    return bool(
        getattr(user, "is_superuser", False)
        or getattr(user, "is_admin", False)
        or getattr(user, "is_analyst", False)
    )


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
        overrides to "Deployment paused"."""
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

    def get_queryset(self):
        qs = Finding.objects.all().select_related("deployment").prefetch_related("evidence")
        user = self.request.user
        if _is_privileged(user):
            qs = qs
        else:
            # Findings on a scan the user launched, or a deployment they own.
            qs = qs.filter(scan__user=user) | qs.filter(deployment__owner=user)
            qs = qs.distinct()
        severity = self.request.query_params.get("severity")
        if severity:
            qs = qs.filter(severity=severity)
        status_q = self.request.query_params.get("status")
        if status_q:
            qs = qs.filter(status=status_q)
        deployment = self.request.query_params.get("deployment")
        if deployment:
            qs = qs.filter(deployment__uuid=deployment)
        return qs


class AssetViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = AssetSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"

    def get_queryset(self):
        qs = Asset.objects.select_related("deployment", "provider").all()
        user = self.request.user
        if _is_privileged(user):
            return qs
        return qs.filter(deployment__owner=user).distinct()


class ProviderViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    serializer_class = ProviderSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "uuid"
    queryset = Provider.objects.all()
