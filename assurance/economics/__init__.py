"""SPINE Economic Exposure: what a technical finding could cost, as a range.

Phases E0 and E1 (``docs/economics/spec-v1.md``): the foundations, and money,
currency, FX and cost-index normalization. Nothing here scores, simulates or
serves anything yet.

- :mod:`assurance.economics.engine` is the pure core: the loss taxonomy, the
  source and confidence vocabularies, the adapter over mythos-core's ISO 4217
  currency table, the separation-of-duties rules, and (E1) money, FX and
  cost-index observations and normalization with their provenance. It imports no
  Django, and of mythos-core only the currency table; a test holds it to that.
- :mod:`assurance.economics.models` is the Django half: the financial sources,
  the model inventory, the scenario, review and override records the separation
  rules are enforced on, and (E1) the FX and cost-index observations. They are
  ``assurance`` models, registered through :mod:`assurance.models` and migrated in
  ``assurance/migrations/``.
- :mod:`assurance.economics.snapshots` registers a committed observation snapshot
  as a source and its observations; ``snapshots/`` holds the one committed, which
  is SYNTHETIC TEST DATA.

This package is never on a stop, pause, stand-down, terminate or revoke path:
:mod:`assurance.models` is the only module that imports it, and a test pins that.
"""
