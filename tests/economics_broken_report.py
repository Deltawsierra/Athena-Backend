"""A pytest plugin, loaded only with ``-p tests.economics_broken_report`` by
``tests/test_economics_report.py::test_a_report_fault_never_takes_down_a_stop``.

It makes ``import assurance.economics.report`` raise, at import, before pytest-django
loads Django -- as a defect in the report would. The scenario endpoints' route module
imports it, and the root URLconf imports that module GUARDED, so the raise leaves
the scenario endpoints and the report unserved and nothing else: the scan's Stop,
``deliver_owed_stops``, ``manage.py check``, the parameter-set routes and the
builder's all stand. Its name does not match ``test_*.py``, so the suite never
collects it.
"""

from __future__ import annotations

import importlib.abc
import sys

BROKEN = frozenset({"assurance.economics.report"})


class _BrokenReport(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in BROKEN:
            raise RuntimeError(f"injected: {name} does not import")
        return None


sys.meta_path.insert(0, _BrokenReport())
