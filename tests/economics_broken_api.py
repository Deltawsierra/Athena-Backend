"""A pytest plugin, loaded only with ``-p tests.economics_broken_api`` by
``tests/test_economics_engine.py::test_an_economics_fault_never_takes_down_a_stop``
(review round 1 of #146, H1).

It makes ``import assurance.economics.api`` raise, at import, before pytest-django
loads Django -- as a defect in the route module, or anything it imports, would.
The root URLconf imports that module, so unguarded the raise took the URLconf
down, and the scan's Stop, ``deliver_owed_stops`` and ``manage.py check`` with it.
Its name does not match ``test_*.py``, so the suite never collects it.
"""

from __future__ import annotations

import importlib.abc
import sys


class _BrokenEconomicsRoutes(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "assurance.economics.api":
            raise RuntimeError("injected: assurance.economics.api does not import")
        return None


sys.meta_path.insert(0, _BrokenEconomicsRoutes())
