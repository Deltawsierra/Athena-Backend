from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .api_views import health

urlpatterns = [
    path("admin/", admin.site.urls),
    # Imported but never routed, so the desktop client's health probe and any
    # load balancer check received a 404.
    path("api/health/", health, name="health"),

    # Auth / JWT
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # Core apps
    path("api/accounts/", include("accounts.urls")),
    path("api/audit/", include("audit.urls")),
    path("api/detection/", include("detection.urls")),
    path("api/pentest/", include("pentest.urls")),
    path("api/failsafe/", include("failsafe.urls")),
    path("api/assurance/", include("assurance.urls")),
]


