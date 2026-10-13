"""Run only by ``tests/test_economics_feeds.py::test_importing_the_feed_modules_reaches_no_host``,
in a fresh pytest under ``tests.economics_no_network``, whose sockets refuse
everything: Django loads, and the feed modules, the data-health route and the fetch
command import, and the route resolves, with no attempt at the network. Its name
does not match ``test_*.py``, so the suite never collects it on its own.
"""

from __future__ import annotations

import importlib

from django.urls import reverse

from tests import economics_no_network


def test_the_feed_modules_import_with_no_network():
    for name in (
        "assurance.economics.engine.feeds",
        "assurance.economics.feeds",
        "assurance.economics.health_api",
        "assurance.management.commands.fetch_financial_source",
    ):
        importlib.import_module(name)
    reverse("deployment-economics-data-health", kwargs={"uuid": "11111111-2222-4333-8444-555555555555"})
    assert economics_no_network.TRIED == []
