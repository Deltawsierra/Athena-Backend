"""A pytest plugin, loaded only with ``-p tests.economics_broken_builder`` by
``tests/test_economics_builder.py::test_a_builder_fault_never_takes_down_a_stop``.

It makes ``import assurance.economics.builder``,
``import assurance.economics.engine.templates`` and the industry-pack registry's
modules raise, at import, before
pytest-django loads Django -- as a defect in the scenario builder or its template
module would. The builder's route module imports both, and the root URLconf imports
that module GUARDED, so the raise leaves the builder's routes unserved and nothing
else: the scan's Stop, ``deliver_owed_stops``, ``manage.py check`` and the
parameter-set routes all stand. Its name does not match ``test_*.py``, so the suite
never collects it.
"""

from __future__ import annotations

import importlib.abc
import sys

BROKEN = frozenset(
    {
        "assurance.economics.builder",
        "assurance.economics.engine.templates",
        # E7 (spec, section 37): the industry-pack registry and the packs, which the
        # builder imports; the parameter set reads only their schema module, which is
        # left whole.
        "assurance.economics.engine.pack_registry",
        "assurance.economics.engine.pack_base",
    }
)


class _BrokenBuilder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name in BROKEN:
            raise RuntimeError(f"injected: {name} does not import")
        return None


sys.meta_path.insert(0, _BrokenBuilder())
