"""The connector registry — name → adapter, and the factory that builds one.

A stable string names each adapter (``"jira"``, ``"servicenow"``,
``"github_issues"``, ``"splunk"``, ``"webhook"``). :func:`build_connector` turns a
name into a configured connector instance; an unknown name raises
:class:`UnknownConnector` with the list of what is available, never a silent
``None``. Building a connector reads config from settings/env by default and
touches no network — an unconfigured connector is inert until it is pushed to.
"""

from __future__ import annotations

from .base import Connector, ConnectorConfig
from .github_issues import GitHubIssuesConnector
from .jira import JiraConnector
from .servicenow import ServiceNowConnector
from .splunk import SplunkConnector
from .webhook import WebhookConnector


class UnknownConnector(ValueError):
    """Raised when a name maps to no registered connector."""


# The single source of truth for name → class. Keyed on each connector's own
# ``name`` so the two can never drift.
_REGISTRY: dict[str, type[Connector]] = {
    cls.name: cls
    for cls in (
        JiraConnector,
        ServiceNowConnector,
        GitHubIssuesConnector,
        SplunkConnector,
        WebhookConnector,
    )
}


def available_connectors() -> list[str]:
    """The registered connector names, sorted — what an API can advertise."""
    return sorted(_REGISTRY)


def get_connector_class(name: str) -> type[Connector]:
    """The connector class for ``name``, or :class:`UnknownConnector`."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise UnknownConnector(
            f"Unknown connector {name!r}. Available: {', '.join(available_connectors())}."
        ) from None


def build_connector(name: str, config: ConnectorConfig | None = None) -> Connector:
    """Build a configured connector by name.

    When ``config`` is given it is used as-is (the seam the per-tenant
    :class:`~assurance.models.ConnectorBinding` layer plugs into via
    ``config_from_binding``). When it is omitted the
    connector reads its config from settings/env via ``config_from_settings``,
    which in an unconfigured environment yields a not-configured config: the
    connector is then inert and any push reports ``"<name> not configured"``.

    An unknown name raises :class:`UnknownConnector`."""
    cls = get_connector_class(name)
    if config is None:
        config = cls.config_from_settings()
    return cls(config)
