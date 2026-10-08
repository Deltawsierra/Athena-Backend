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
    """The closure forward's Minotaur credential (:mod:`assurance.closure_forward`): a
    WARNING when one secret is set as both Blue's outcome-recorder key and the legacy
    runner key (``assurance.W305``: nothing is sent then), and when the shared runner
    key forwards alone (``assurance.W304``: role separation is not in force).

    Never an ``Error``, and never raises: an error here would refuse every command that
    runs the system checks -- ``migrate``, ``runserver``, and the scheduled scan-Stop
    delivery ``deliver_owed_stops`` -- and nothing about a dataset forward may hold back
    a Stop. Said by ``manage.py check``, and once by each process at start."""
    from .closure_forward import LEGACY_RUNNER_KEY, OUTCOMES_KEY, credential_problems

    hint = (
        f"Set {OUTCOMES_KEY} to a key of Minotaur-Backend's outcome-recorder role, and unset "
        f"{LEGACY_RUNNER_KEY}."
    )
    try:
        problems = credential_problems()
    except Exception as exc:  # noqa: BLE001 - a check never refuses a command, a Stop's least of all
        return [
            checks.Warning(
                f"the closure forward's credential could not be read ({type(exc).__name__}): "
                "forwarding is off",
                hint=hint,
                id="assurance.W305",
            )
        ]
    return [checks.Warning(message, hint=hint, id=ident) for _level, ident, message in problems]
