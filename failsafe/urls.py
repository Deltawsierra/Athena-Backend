from django.urls import path

from . import views

app_name = "failsafe"

urlpatterns = [
    # Operator console
    path("commands/", views.commands, name="commands"),
    path("commands/<uuid:cmd_uuid>/", views.command_detail, name="command-detail"),
    path("commands/<uuid:cmd_uuid>/signatures/", views.submit_signature, name="submit-signature"),
    path("commands/<uuid:cmd_uuid>/cancel/", views.cancel_command, name="cancel-command"),
    path("state/", views.state, name="state"),
    path("audit/", views.audit, name="audit"),
    # Engine poll (poll-token auth, not operator JWT)
    path("pending/", views.pending, name="pending"),
]
