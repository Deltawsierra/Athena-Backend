"""A pytest plugin, loaded only with ``-p tests.economics_probabilistic_poisoned``
by ``tests/test_economics_simulation.py::test_a_broken_probabilistic_engine_never_takes_down_the_scan_stop``.

It makes numpy and the probabilistic engine's modules
(``assurance.economics.engine.distributions``, ``.simulation``, step 7b's
``.scenario_simulation`` and ``.twins``, and ``assurance.economics.simulation_service``;
step 8's ``.sensitivity`` and ``.grade``, ``assurance.economics.validity_service`` and
``.receipt_service``, and ``mythos_core.exposure_receipt``; step 6's ``.charts`` and
``assurance.economics.charts_service``) unimportable, as an
import-time fault in any of them would, before pytest-django loads Django.
The scan's Stop must still resolve, answer and be saved. It is never loaded by
the suite itself: its name does not match ``test_*.py``.
"""

from __future__ import annotations

import sys

POISONED = (
    "numpy",
    "assurance.economics.engine.distributions",
    "assurance.economics.engine.simulation",
    "assurance.economics.engine.scenario_simulation",
    "assurance.economics.engine.twins",
    "assurance.economics.simulation_service",
    "assurance.economics.engine.sensitivity",
    "assurance.economics.engine.grade",
    "assurance.economics.validity_service",
    "assurance.economics.receipt_service",
    "mythos_core.exposure_receipt",
    "assurance.economics.engine.charts",
    "assurance.economics.charts_service",
)


class _Poison:
    def find_spec(self, name, path=None, target=None):
        if any(name == poisoned or name.startswith(poisoned + ".") for poisoned in POISONED):
            raise ImportError("poisoned: " + name)
        return None


for _name in list(sys.modules):
    if any(_name == poisoned or _name.startswith(poisoned + ".") for poisoned in POISONED):
        raise RuntimeError(f"{_name} was imported before the poison was installed")
sys.meta_path.insert(0, _Poison())
