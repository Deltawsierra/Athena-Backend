"""URL routes for the assurance API, mounted under /api/assurance/."""

from __future__ import annotations

import logging

from rest_framework.routers import DefaultRouter

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

logger = logging.getLogger(__name__)

# Economic Exposure's one route module (docs/economics/spec-v1.md, sections 2 and
# 19): the customer parameter-set routes, none of them a stop. Imported GUARDED.
# This module is the root URLconf's, and an import that raised here would take the
# URLconf down, and every route with it: the scan's Stop, every other stop, and the
# URL check `manage.py check` and `deliver_owed_stops` run first. An economics
# fault refuses economics and nothing else, so a module that will not import is
# logged and its routes are simply not served.
try:
    from .economics.api import urlpatterns as economics_urlpatterns
except Exception:
    logger.exception("Economic Exposure's routes could not be loaded; they are not served, and nothing else is")
    economics_urlpatterns = []

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
