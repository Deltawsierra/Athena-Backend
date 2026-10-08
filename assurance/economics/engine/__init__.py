"""The pure core of Economic Exposure: vocabularies, the currency table and the
separation-of-duties rules, with no Django and no database.

Everything a calculation will later depend on is stated here once, as data and
pure functions, so the Django half (:mod:`assurance.economics.models`), the
fixtures and the tests all read the same codes:

- :mod:`.taxonomy`: the fifteen loss families, each with a stable code;
- :mod:`.provenance`: where a parameter came from (``source_type``), a source's
  licence class and its trust tier;
- :mod:`.confidence`: the confidence grades A, B, C, D and Unknown;
- :mod:`.currency`: the ISO 4217 table (minor units, active or retired,
  successor), read from the reviewed data file beside it;
- :mod:`.governance`: who may review a scenario, how many people approve a
  sensitive override, which sources a production run may use, and the refusal
  code each rule gives.

No module in this package may import Django, the REST framework, or any other
part of :mod:`assurance` (which does). ``tests/test_economics_engine.py`` imports
it in a fresh interpreter with Django poisoned and fails if any import reaches it.
"""
