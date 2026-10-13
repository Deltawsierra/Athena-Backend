"""SPINE Economic Exposure: what a technical finding could cost, as a range.

Phases E0 and E1 (``docs/economics/spec-v1.md``): the foundations; money,
currency, FX and cost-index normalization; and the deterministic scenario engine
(parameters, the formula catalogue, loss events and components, insurance) with
the customer parameter set and its API; the scenario builder; and (phase E2) the
distributions, the seeded sampler and the simulation of a stored scenario version.

- :mod:`assurance.economics.engine` is the pure core: the loss taxonomy, the
  source and confidence vocabularies, the adapter over mythos-core's ISO 4217
  currency table, the separation-of-duties rules, and (E1) money, FX and
  cost-index observations and normalization with their provenance, and the
  scenario engine. It imports no Django, and of mythos-core only the currency
  table; a test holds it to that.
- :mod:`assurance.economics.models` is the Django half: the financial sources,
  the model inventory, the scenario, review and override records the separation
  rules are enforced on, (E1) the FX and cost-index observations, and the
  customer parameter sets, financial parameters, loss events and components. They are
  ``assurance`` models, registered through :mod:`assurance.models` and migrated in
  ``assurance/migrations/``.
- :mod:`assurance.economics.snapshots` registers a committed observation snapshot
  as a source and its observations; ``snapshots/`` holds the one committed, which
  is SYNTHETIC TEST DATA.

- :mod:`assurance.economics.api` is the customer parameter-set routes, mounted by
  :mod:`assurance.urls`.
- :mod:`assurance.economics.builder` is the scenario builder (MVP step 5): it builds
  a scenario's causal loss events from SPINE effects and findings through the
  templates of :mod:`assurance.economics.engine.templates`;
  :mod:`assurance.economics.scenario_api` is its two routes, mounted by
  :mod:`assurance.urls` in a guard of its own. Nothing on Django's load path imports
  either.
- :mod:`assurance.economics.simulation_service` simulates a stored scenario version
  and records the run (MVP step 7b); it imports the probabilistic engine, and
  numpy, only when called. No route serves it yet, and nothing on Django's load
  path imports it.
- :mod:`assurance.economics.validity_service` makes a stored result's sensitivity
  analysis, confidence grade and Financial Exposure Validity Card, and
  :mod:`assurance.economics.receipt_service` its signed Financial Exposure Receipt
  (MVP step 8), recording each once per result. Both import the engine, numpy and
  ``mythos_core.exposure_receipt`` only when called; no route serves them yet, and
  nothing on Django's load path imports them.
- :mod:`assurance.economics.feeds` fetches a live feed into the snapshot store and
  says how fresh each feed source is (MVP step 10), run by the operator's ``manage.py
  fetch_financial_source``; :mod:`assurance.economics.health_api` is the data-health
  route, mounted by :mod:`assurance.urls` in a guard of its own, which imports the
  feed module only inside its view.

This package is never on a stop, pause, stand-down, terminate or revoke path:
:mod:`assurance.models` (registering the models) and :mod:`assurance.urls`
(mounting the routes, none of them a stop) are the only modules that import it,
and a test pins that.
"""
