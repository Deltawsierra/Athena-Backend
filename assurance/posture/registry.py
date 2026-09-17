"""The posture registry — name → domain assessment, and the factory that builds one.

A stable string names each credential-gated domain (``"cloud"``, ``"secrets"``,
``"repo"``). :func:`build_assessment` turns a name into a configured
:class:`~assurance.posture.base.PostureAssessment`; an unknown name raises
:class:`UnknownPostureDomain` with the list of what is available, never a silent
``None``. Building a domain reads config from settings/env by default and touches
no network — an unconfigured domain is inert until it is assessed with a fetcher.
Mirrors :mod:`assurance.connectors.registry`.
"""

from __future__ import annotations

from .base import PostureAssessment, PostureConfig
from .cloud import CloudPosture
from .repo import RepoPosture
from .secrets import SecretsPosture


class UnknownPostureDomain(ValueError):
    """Raised when a name maps to no registered posture domain."""


# The single source of truth for name → class, keyed on each domain's own ``name``
# so the two can never drift.
_REGISTRY: dict[str, type[PostureAssessment]] = {
    cls.name: cls
    for cls in (
        CloudPosture,
        SecretsPosture,
        RepoPosture,
    )
}


def available_domains() -> list[str]:
    """The registered posture-domain names, sorted — what an API can advertise."""
    return sorted(_REGISTRY)


def get_assessment_class(name: str) -> type[PostureAssessment]:
    """The assessment class for ``name``, or :class:`UnknownPostureDomain`."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise UnknownPostureDomain(
            f"Unknown posture domain {name!r}. Available: {', '.join(available_domains())}."
        ) from None


def build_assessment(name: str, config: PostureConfig | None = None) -> PostureAssessment:
    """Build a configured posture assessment by name.

    When ``config`` is given it is used as-is (the seam a per-tenant config layer
    plugs into later — the deferred live-wiring follow-up). When it is omitted the
    domain reads its config from settings/env via ``config_from_settings``, which
    in an unconfigured environment yields a not-configured config: the domain is
    then inert and any :meth:`~assurance.posture.base.PostureAssessment.assess`
    reports ``connected: false`` and makes no fetch.

    An unknown name raises :class:`UnknownPostureDomain`."""
    cls = get_assessment_class(name)
    if config is None:
        config = cls.config_from_settings()
    return cls(config)
