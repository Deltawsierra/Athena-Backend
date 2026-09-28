from django.contrib import admin
from django.urls import path, include

from safety.refresh import RefreshView
from safety.sign_in import SignInView

from .api_views import health

urlpatterns = [
    path("admin/", admin.site.urls),
    # Imported but never routed, so the desktop client's health probe and any
    # load balancer check received a 404.
    path("api/health/", health, name="health"),

    # Auth / JWT
    # Failed sign-ins are limited per address and username, not by the shared
    # anonymous bucket, which any flood from the operator's address emptied.
    path("api/token/", SignInView.as_view(), name="token_obtain_pair"),
    # A refresh spends its refresh token exactly once, however many arrive
    # together with it, and only for an account that exists and is active.
    path("api/token/refresh/", RefreshView.as_view(), name="token_refresh"),

    # Core apps
    path("api/accounts/", include("accounts.urls")),
    path("api/audit/", include("audit.urls")),
    path("api/detection/", include("detection.urls")),
    path("api/pentest/", include("pentest.urls")),
    path("api/failsafe/", include("failsafe.urls")),
    path("api/assurance/", include("assurance.urls")),
]


