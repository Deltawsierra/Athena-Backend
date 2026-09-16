from django.apps import AppConfig


class AssuranceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "assurance"
    verbose_name = "Assurance (system of record)"

    def ready(self):
        # Connect the post_save receiver that ingests a scan into the assurance
        # data model when it completes (Phase 0.1b).
        from . import signals  # noqa: F401
