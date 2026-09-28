"""System checks for this app's settings."""

from __future__ import annotations

from django.core import checks


def dispatch_settings(app_configs=None, **kwargs):
    """A dispatch setting that is not a number it can be is an error: named here,
    by ``manage.py check`` (and so by ``migrate`` and ``runserver``), and logged once
    by each process at start (:meth:`AssuranceConfig.ready`), which then uses its
    default."""
    from .dispatch import settings_problems

    return [
        checks.Error(problem, hint="Set it to a number, or unset it for the default.", id="assurance.E303")
        for problem in settings_problems()
    ]
