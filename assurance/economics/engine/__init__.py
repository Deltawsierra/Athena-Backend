"""The pure core of Economic Exposure: vocabularies, the currency table, the
separation-of-duties rules, and money, FX and cost-index normalization, with no
Django and no database.

Everything a calculation will later depend on is stated here once, as data and
pure functions, so the Django half (:mod:`assurance.economics.models`), the
fixtures and the tests all read the same codes:

- :mod:`.taxonomy`: the fifteen loss families, each with a stable code;
- :mod:`.provenance`: where a parameter came from (``source_type``), a source's
  licence class and its trust tier;
- :mod:`.confidence`: the confidence grades A, B, C, D and Unknown;
- :mod:`.currency`: the ISO 4217 table (minor units, active or retired,
  successor), which is mythos-core's one table, read through a thin adapter that
  refuses, on use and never at import, any table but the one pinned;
- :mod:`.governance`: who may review a scenario, how many people approve a
  sensitive override, which sources a production run may use, and the refusal
  code each rule gives;
- :mod:`.money` (E1): ``Money``, a ``Decimal`` and a code; full-precision
  arithmetic, display rounding, and the engine's refusal codes;
- :mod:`.fx` (E1): FX observations, the book and the policy a conversion reads,
  and the conversion with its provenance;
- :mod:`.cost_index` (E1): cost-index observations and the indexing step;
- :mod:`.normalization` (E1): native amount, event-date FX, cost index,
  valuation-date FX, in that order, with the provenance chain;
- :mod:`.snapshot` (E1): reading a committed observation snapshot and its hash.

No module in this package may import Django, the REST framework, any part of
mythos-core but :mod:`mythos_core.currency`, or any other part of
:mod:`assurance` (which does). ``tests/test_economics_engine.py`` imports it in a
fresh interpreter with all of those poisoned and fails if any import reaches one.
"""
