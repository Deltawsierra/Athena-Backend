"""A pytest plugin, loaded only with ``-p tests.economics_missing_core`` by
``tests/test_economics_engine.py::test_an_economics_fault_never_takes_down_a_stop``
(review round 1 of #146, H2).

It makes ``mythos_core.currency`` unimportable (``sys.modules`` holds ``None`` for
it), at import, before pytest-django loads Django. ``assurance.models`` imports
the economics models, which import the money engine and its currency adapter;
when the adapter imported core's module at import, the missing module took
``django.setup()`` down, and every stop with it. Its name does not match
``test_*.py``, so the suite never collects it.
"""

from __future__ import annotations

import sys

core = sys.modules.get("mythos_core")
if core is not None and "currency" in dir(core):
    delattr(core, "currency")
sys.modules["mythos_core.currency"] = None
