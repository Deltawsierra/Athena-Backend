from django.contrib import admin
from django.urls import path, include

from safety.refresh import RefreshView
from safety.revoke import RevokeView
from safety.sign_in import SignInView

from .api_views import health
from .readiness import readiness

urlpatterns = [
    path("admin/", admin.site.urls),
    # Imported but never routed, so the desktop client's health probe and any
    # load balancer check received a 404.
    path("api/health/", health, name="health"),
    # Readiness beside liveness: each dependency named, ok / degraded / unknown, with
    # why, from bounded checks (config.readiness). Liveness above is unchanged. Under
    # /api/health/, so the gateway skips it as it skips liveness (audit.middleware).
    path("api/health/ready/", readiness, name="readiness"),

    # Auth / JWT
    # Failed sign-ins are limited per address and username, not by the shared
    # anonymous bucket, which any flood from the operator's address emptied.
    path("api/token/", SignInView.as_view(), name="token_obtain_pair"),
    # A refresh spends its refresh token exactly once, however many arrive
    # together with it, and only for an account that exists and is active.
    path("api/token/refresh/", RefreshView.as_view(), name="token_refresh"),
    # Sign-out: the refresh token sent is revoked for good. A revoke only takes
    # access away, so it is a stop (safety.stops), and never refused.
    path("api/token/revoke/", RevokeView.as_view(), name="token_revoke"),

    # Core apps
    path("api/accounts/", include("accounts.urls")),
    path("api/audit/", include("audit.urls")),
    path("api/detection/", include("detection.urls")),
    path("api/pentest/", include("pentest.urls")),
    path("api/failsafe/", include("failsafe.urls")),
    path("api/assurance/", include("assurance.urls")),
]



# A failure no view caught answers by its route's operation class (G14; owner
# decision 13): an evidence read unknown, an effect held, an assessment audit
# incomplete, each with the dependency that failed -- never a bare "Server Error
# (500)" that names nothing. A stop, and anything it cannot place, keeps Django's
# own 500 unchanged; it runs only after a view has raised (safety.degraded).
handler500 = "safety.degraded.server_error"
