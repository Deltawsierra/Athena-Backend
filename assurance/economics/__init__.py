"""SPINE Economic Exposure: what a technical finding could cost, as a range.

Phase E0 (``docs/economics/spec-v1.md``): the foundations only. Nothing here
scores, simulates or serves anything yet.

- :mod:`assurance.economics.engine` is the pure core: the loss taxonomy, the
  source and confidence vocabularies, the ISO 4217 currency table and the
  separation-of-duties rules. It imports no Django, and a test holds it to that.
- :mod:`assurance.economics.models` is the Django half: the financial sources,
  the model inventory, and the scenario, review and override records the
  separation rules are enforced on. They are ``assurance`` models, registered
  through :mod:`assurance.models` and migrated in ``assurance/migrations/``.

This package is never on a stop, pause, stand-down, terminate or revoke path:
:mod:`assurance.models` is the only module that imports it, and a test pins that.
"""
