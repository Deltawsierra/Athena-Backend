from django.apps import AppConfig


class AssuranceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "assurance"
    verbose_name = "Assurance (system of record)"

    def ready(self):
        # Connect the post_save receiver that ingests a scan into the assurance
        # data model when it completes. This is the Phase 0.1b wiring, and it is
        # complete: the Phase 0.1 data model (assurance.models), the ingest
        # pipeline (assurance.ingest), and this on-commit signal (assurance.signals)
        # are all in place and covered by tests.test_assurance_ingest_signal — no
        # data-model work remains outstanding under this phase.
        from . import signals  # noqa: F401
