"""A pytest plugin, loaded only with ``-p tests.economics_probabilistic_poisoned``
by ``tests/test_economics_simulation.py::test_a_broken_probabilistic_engine_never_takes_down_the_scan_stop``.

It makes numpy and the probabilistic engine's two modules
(``assurance.economics.engine.distributions`` and ``.simulation``) unimportable,
as an import-time fault in any of them would, before pytest-django loads Django.
The scan's Stop must still resolve, answer and be saved. It is never loaded by
the suite itself: its name does not match ``test_*.py``.
"""

from __future__ import annotations

import sys

POISONED = ("numpy", "assurance.economics.engine.distributions", "assurance.economics.engine.simulation")


class _Poison:
    def find_spec(self, name, path=None, target=None):
        if any(name == poisoned or name.startswith(poisoned + ".") for poisoned in POISONED):
            raise ImportError("poisoned: " + name)
        return None


for _name in list(sys.modules):
    if any(_name == poisoned or _name.startswith(poisoned + ".") for poisoned in POISONED):
        raise RuntimeError(f"{_name} was imported before the poison was installed")
sys.meta_path.insert(0, _Poison())
