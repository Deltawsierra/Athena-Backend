"""A pytest plugin, loaded only with ``-p tests.economics_broken_feeds`` by
``tests/test_economics_feeds.py::test_a_feed_fault_never_takes_down_a_stop``.

It makes ``import assurance.economics.feeds`` raise, at import, before pytest-django
loads Django -- as a defect in the feed fetch or its freshness rules would. Nothing
Django loads at start imports it: the data-health route and the Validity Card import
it inside a call. So the raise leaves the data-health route answering an error and
nothing else: the scan's Stop, ``deliver_owed_stops``, ``manage.py check`` and every
other economics route all stand. Its name does not match ``test_*.py``, so the suite
never collects it.
"""

from __future__ import annotations

import importlib.abc
import sys

BROKEN = frozenset({"assurance.economics.feeds"})


class _BrokenFeeds(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in BROKEN:
            raise RuntimeError(f"injected: {name} does not import")
        return None


sys.meta_path.insert(0, _BrokenFeeds())
