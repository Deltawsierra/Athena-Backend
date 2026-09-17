"""URL routes for the assurance API, mounted under /api/assurance/."""

from __future__ import annotations

from rest_framework.routers import DefaultRouter

from .views import (
    AssetViewSet,
    DeploymentViewSet,
    FindingViewSet,
    ProviderAssertionViewSet,
    ProviderViewSet,
    UnknownViewSet,
)

router = DefaultRouter()
router.register(r"deployments", DeploymentViewSet, basename="deployment")
router.register(r"findings", FindingViewSet, basename="finding")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"provider-assertions", ProviderAssertionViewSet, basename="provider-assertion")
router.register(r"unknowns", UnknownViewSet, basename="unknown")

urlpatterns = router.urls
