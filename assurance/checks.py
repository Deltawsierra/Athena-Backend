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


def closure_forward_credentials(app_configs=None, **kwargs):
    """The closure forward's Minotaur credential (:mod:`assurance.closure_forward`): an
    error when one secret is set as both Blue's outcome-recorder key and the legacy
    runner key -- nothing is sent then -- and a warning when the shared runner key
    forwards alone, since role separation is not in force. Said by ``manage.py
    check``, and once by each process at start."""
    from .closure_forward import LEGACY_RUNNER_KEY, OUTCOMES_KEY, credential_problems

    hint = (
        f"Set {OUTCOMES_KEY} to a key of Minotaur-Backend's outcome-recorder role, and unset "
        f"{LEGACY_RUNNER_KEY}."
    )
    found = []
    for level, ident, message in credential_problems():
        kind = checks.Error if level == "error" else checks.Warning
        found.append(kind(message, hint=hint, id=ident))
    return found
