"""Deployment checks for the stop-safety rules (``manage.py check --deploy``)."""

from django.core.checks import Tags, Warning, register


def per_process_database(settings_dict):
    """Whether a database with these settings exists only inside one process:
    an in-memory SQLite database, which each worker would have its own of."""
    engine = str(settings_dict.get("ENGINE") or "")
    name = str(settings_dict.get("NAME") or "")
    if not engine.endswith("sqlite3"):
        return False
    return name in ("", ":memory:") or name.startswith("file::memory:") or "mode=memory" in name


@register(Tags.security, deploy=True)
def sign_in_limits_are_shared(app_configs, **kwargs):
    """The sign-in limits (safety.sign_in) count in the database, so that every
    worker process counts against one number. A store each process has its own
    of multiplies both limits by the number of workers."""
    from django.db import connections, router

    from .models import SignInCount

    alias = router.db_for_write(SignInCount)
    if per_process_database(connections[alias].settings_dict):
        return [
            Warning(
                "The sign-in limits count in a database that exists only inside one process "
                f"({alias!r} is an in-memory SQLite database), so every worker has limits of its own.",
                hint="Point that database at a file or a server that every worker shares.",
                id="safety.W001",
            )
        ]
    return []
