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

# Economic Exposure's route modules (docs/economics/spec-v1.md, sections 2, 19 and 24,
# section 27 for step 6's, section 28 for step 13's and section 29 for step 10's): the
# customer parameter-set routes, the scenario builder's, the scenario endpoints with the
# report, the remediation option with its ROI, and the data-health route, none of them a
# stop. Each is imported GUARDED,
# in a guard of its own. This module is the root URLconf's, and an import that
# raised here would take the URLconf down, and every
# route with it: the scan's Stop, every other stop, and the URL check
# `manage.py check` and `deliver_owed_stops` run first. An economics fault refuses
# economics and nothing else, so a module that will not import is logged and its
# routes are simply not served -- and a fault in the builder, the report or the
# remediation routes leaves the other economics routes served.
try:
    from .economics.api import urlpatterns as economics_urlpatterns
except Exception:
    logger.exception("Economic Exposure's routes could not be loaded; they are not served, and nothing else is")
    economics_urlpatterns = []
try:
    from .economics.scenario_api import urlpatterns as economics_scenario_urlpatterns
except Exception:
    logger.exception(
        "Economic Exposure's scenario-builder routes could not be loaded; they are not served, and nothing else is"
    )
    economics_scenario_urlpatterns = []
try:
    from .economics.report_api import urlpatterns as economics_report_urlpatterns
except Exception:
    logger.exception(
        "Economic Exposure's scenario and report routes could not be loaded; they are not served, and nothing else is"
    )
    economics_report_urlpatterns = []
try:
    from .economics.remediation_api import urlpatterns as economics_remediation_urlpatterns
except Exception:
    logger.exception(
        "Economic Exposure's remediation routes could not be loaded; they are not served, and nothing else is"
    )
    economics_remediation_urlpatterns = []
try:
    from .economics.health_api import urlpatterns as economics_health_urlpatterns
except Exception:
    logger.exception(
        "Economic Exposure's data-health route could not be loaded; it is not served, and nothing else is"
    )
    economics_health_urlpatterns = []

router = DefaultRouter()
router.register(r"deployments", DeploymentViewSet, basename="deployment")
router.register(r"findings", FindingViewSet, basename="finding")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"provider-assertions", ProviderAssertionViewSet, basename="provider-assertion")
router.register(r"unknowns", UnknownViewSet, basename="unknown")
router.register(r"claims", ClaimViewSet, basename="claim")
router.register(r"retest-requirements", RetestRequirementViewSet, basename="retest-requirement")

urlpatterns = (
    router.urls
    + economics_urlpatterns
    + economics_scenario_urlpatterns
    + economics_report_urlpatterns
    + economics_remediation_urlpatterns
    + economics_health_urlpatterns
)
