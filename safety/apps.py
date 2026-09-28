from django.apps import AppConfig


class SafetyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "safety"

    def ready(self):
        # The deployment check on the sign-in limiter's store.
        from . import checks  # noqa: F401
