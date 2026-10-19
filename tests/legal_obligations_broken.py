"""A pytest plugin, loaded only with ``-p tests.legal_obligations_broken`` by
``tests/test_legal_obligation_routes.py::test_a_legal_obligations_fault_never_takes_down_a_stop``.

It makes ``import assurance.legal_api`` raise, at import, before pytest-django loads
Django -- as a defect in the legal-obligations routes would. The root URLconf imports
that module GUARDED, so the raise leaves its three routes unserved and nothing else:
the scan's Stop, ``deliver_owed_stops``, ``manage.py check`` and every other route
stand (``tests/legal_obligations_fault_cases.py``). ``ASKED`` records that the import
was attempted, so the cases can tell a guard that caught the fault from a URLconf that
never asked for the module. Its name does not match ``test_*.py``, so the suite never
collects it.
"""

from __future__ import annotations

import importlib.abc
import sys

BROKEN = frozenset({"assurance.legal_api"})

#: Each broken module something tried to import, in order.
ASKED: list[str] = []


class _BrokenLegalObligations(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in BROKEN:
            ASKED.append(name)
            raise RuntimeError(f"injected: {name} does not import")
        return None


sys.meta_path.insert(0, _BrokenLegalObligations())
