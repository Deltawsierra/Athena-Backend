"""A pytest plugin, loaded only with ``-p tests.economics_broken_remediation`` by
``tests/test_economics_remediation.py::test_a_remediation_fault_never_takes_down_a_stop``.

It makes ``import assurance.economics.remediation_service`` raise, at import, before
pytest-django loads Django -- as a defect in the remediation step would. Its route
module imports it, and the root URLconf imports that module GUARDED, so the raise
leaves the remediation option and ROI routes unserved and nothing else: the scan's
Stop, ``deliver_owed_stops``, ``manage.py check``, the parameter-set routes, the
builder's and the scenario endpoints with the report all stand. Its name does not
match ``test_*.py``, so the suite never collects it.
"""

from __future__ import annotations

import importlib.abc
import sys

BROKEN = frozenset({"assurance.economics.remediation_service"})


class _BrokenRemediation(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in BROKEN:
            raise RuntimeError(f"injected: {name} does not import")
        return None


sys.meta_path.insert(0, _BrokenRemediation())
