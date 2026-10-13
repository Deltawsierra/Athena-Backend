"""A pytest plugin, loaded only with ``-p tests.economics_broken_portfolio`` by
``tests/test_economics_portfolio.py::test_a_portfolio_fault_never_takes_down_a_stop``.

It makes ``import assurance.economics.portfolio`` raise, at import, before
pytest-django loads Django -- as a defect in the portfolio would. The portfolio's
route module imports it, and the root URLconf imports that module GUARDED, so the
raise leaves the portfolio's two routes unserved and nothing else: the scan's Stop,
``deliver_owed_stops``, ``manage.py check`` and every other economics route stand.
Its name does not match ``test_*.py``, so the suite never collects it.
"""

from __future__ import annotations

import importlib.abc
import sys

BROKEN = frozenset({"assurance.economics.portfolio"})


class _BrokenPortfolio(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in BROKEN:
            raise RuntimeError(f"injected: {name} does not import")
        return None


sys.meta_path.insert(0, _BrokenPortfolio())
