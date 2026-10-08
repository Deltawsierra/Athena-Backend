"""A pytest plugin, loaded only with ``-p tests.economics_mismatched_core`` by
``tests/test_economics_engine.py::test_a_changed_core_table_never_takes_down_the_scan_stop``.

It changes one entry of mythos-core's currency table (USD gets three minor units)
as a core bump that changed the table would, and it does so at import, before
pytest-django loads Django -- so ``assurance.economics.engine.currency`` checks its
pin against the changed table on the first economics use (it checks nothing at
import).
It is never loaded by the suite itself: its name does not match ``test_*.py``.
"""

from __future__ import annotations

import dataclasses
import types

import mythos_core.currency as _core

_table = dict(_core.CURRENCIES)
_table["USD"] = dataclasses.replace(_table["USD"], minor_units=3)
_core.CURRENCIES = types.MappingProxyType(_table)
