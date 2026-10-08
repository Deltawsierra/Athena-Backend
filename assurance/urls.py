"""URL routes for the assurance API, mounted under /api/assurance/."""

from __future__ import annotations

from rest_framework.routers import DefaultRouter

# Economic Exposure's one route module (docs/economics/spec-v1.md, section 19):
# the customer parameter-set routes. None of them is a stop, and the module does
# nothing at import but define its views.
from .economics.api import urlpatterns as economics_urlpatterns
from .views import (
    AssetViewSet,
    ClaimViewSet,
    DeploymentViewSet,
    FindingViewSet,
    ProviderAssertionViewSet,
    ProviderViewSet,
    RetestRequirementViewSet,
    UnknownViewSet,
)

router = DefaultRouter()
router.register(r"deployments", DeploymentViewSet, basename="deployment")
router.register(r"findings", FindingViewSet, basename="finding")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"provider-assertions", ProviderAssertionViewSet, basename="provider-assertion")
router.register(r"unknowns", UnknownViewSet, basename="unknown")
router.register(r"claims", ClaimViewSet, basename="claim")
router.register(r"retest-requirements", RetestRequirementViewSet, basename="retest-requirement")

urlpatterns = router.urls + economics_urlpatterns
