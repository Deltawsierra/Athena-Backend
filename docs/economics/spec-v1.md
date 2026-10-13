# SPINE Economic Exposure, specification v1 (phases E0 and E1)

Economic Exposure estimates what a technical finding could cost a customer, as a
range with its confidence, sources and assumptions. It is a SPINE capability, not
a new product: a consequence layer on the same graph of evidence, claims, effects
and authority. The owner granted it a freeze exception on 7 Oct 2026 (FREEZE.md in
Mythos-Core, owner exception 9) and adopted the plan's decisions on 8 Oct 2026.

This file is the specification for phase E0, the foundations, and phase E1,
money, currency, FX and cost-index normalization, with the deterministic scenario
engine (MVP step 4): parameters and their units, the formula catalogue, loss
events and their components, insurance, and the customer parameter set with its
API; and the scenario builder (MVP step 5, section 24), which builds a scenario's
loss events from SPINE effects and findings through six banking templates. It states the calculation policy every later step follows, the vocabularies
and the currency table, the records and who may write them, the governance rules,
how an amount is held, converted and normalized and with what provenance, the
observation data, how a loss component is computed and with what invariants, and
what this version does not do. The scenario engine computes deterministic low, base
and high ranges, and the routes it serves are the customer parameter set's (section
19) and the scenario builder's (section 24). The distribution catalogue and the seeded
sampler (phase E2, section 23) are pure; MVP step 7b (section 25) wires them to the
formulas and the loss model through a service that simulates a stored scenario version
and records the result, and serves no route; and MVP step 8 (section 26) analyses a
stored result's sensitivity on its own draws, grades it, writes its Financial
Exposure Validity Card and signs its Financial Exposure Receipt, and serves no route
either. MVP step 6 gives a stated distribution and the scenario's frequency their
writers, the parameter set and the builder, and holds every stated distribution to
its row's figures from both sides, and the frequency by the rate its count implies
(sections 19.4 and 25.1); and it serves steps 5, 7b and 8 (section 27): a scenario
version with its parameters' provenance, a simulation of it under a named policy,
and the deterministic report JSON of a stored result, with the banner a result graded
Unknown carries.

## Contents

1. [Status and scope](#1-status-and-scope)
2. [Safety](#2-safety)
3. [Calculation policy](#3-calculation-policy)
4. [Vocabularies](#4-vocabularies)
5. [The currency table](#5-the-currency-table)
6. [Records and their permitted writers](#6-records-and-their-permitted-writers)
7. [Governance rules and refusal codes](#7-governance-rules-and-refusal-codes)
8. [References into SPINE](#8-references-into-spine)
9. [Open FAIR](#9-open-fair)
10. [Limitations](#10-limitations)
11. [Money](#11-money)
12. [FX, cost indices and normalization](#12-fx-cost-indices-and-normalization)
13. [Observation data and the synthetic snapshot](#13-observation-data-and-the-synthetic-snapshot)
14. [Parameters and units](#14-parameters-and-units)
15. [The formula catalogue](#15-the-formula-catalogue)
16. [Loss events, components and totals](#16-loss-events-components-and-totals)
17. [Insurance](#17-insurance)
18. [The invariants](#18-the-invariants)
19. [The customer parameter set and its API](#19-the-customer-parameter-set-and-its-api)
    (19.4, MVP step 6: [the writer of stated distributions and the frequency](#194-the-writer-of-stated-distributions-and-the-frequency-mvp-step-6))
20. [The scenario records](#20-the-scenario-records)
21. [Known-answer fixtures](#21-known-answer-fixtures)
22. [Limitations of the scenario engine, and decisions for the owner](#22-limitations-of-the-scenario-engine-and-decisions-for-the-owner)

Phase E2, MVP step 7a, after the scenario engine's sections 14 to 22 (MVP step 4):

23. [Distributions and simulation](#23-distributions-and-simulation)

The scenario builder, MVP step 5 (merged after step 7a):

24. [The scenario builder (MVP step 5)](#24-the-scenario-builder-mvp-step-5)

Phase E2, MVP step 7b, wiring step 7a to steps 4 and 5:

25. [Wiring the simulation (MVP step 7b)](#25-wiring-the-simulation-mvp-step-7b)

MVP step 8, on step 7b's stored result:

26. [Sensitivity, grade, Validity Card and receipt (MVP step 8)](#26-sensitivity-grade-validity-card-and-receipt-mvp-step-8)

MVP step 6, serving steps 5, 7b and 8:

27. [The scenario endpoints and the report (MVP step 6)](#27-the-scenario-endpoints-and-the-report-mvp-step-6)

MVP step 13, one remediation option per scenario version, on steps 7b, 8 and 6:

28. [One remediation option, its residual run and its economics (MVP step 13)](#28-one-remediation-option-its-residual-run-and-its-economics-mvp-step-13)

## 1. Status and scope

| | |
|---|---|
| Phase | E0: taxonomy, source registry, model governance, currency rules. E1: money, the one currency table, FX and cost-index observations, normalization; the scenario engine (MVP step 4): parameters, formulas, loss events and components, insurance, the customer parameter set and its API; and the scenario builder (MVP step 5): the causal graph, six banking templates, the builder and its routes |
| Code | `assurance/economics/`: the pure core in `engine/` (E1: `money.py`, `fx.py`, `cost_index.py`, `normalization.py`, `snapshot.py`; scenarios: `parameters.py`, `formulas.py`, `loss.py`, `parameter_set.py`; the builder: `templates.py`), the Django records in `models.py`, the snapshot loader in `snapshots.py`, the parameter-set routes in `api.py`, the scenario builder in `builder.py` and its routes in `scenario_api.py`; step 8 (section 26): `engine/sensitivity.py` and `engine/grade.py`, the Validity Card in `validity_service.py`, the receipt in `receipt_service.py`; step 6 (section 27): the scenario endpoints in `report_api.py`, the report in `report.py`, the chart series in `charts_service.py` and `engine/charts.py` |
| Migrations | `assurance/migrations/0060_economic_exposure_foundations.py` (E0), `0061_fx_and_cost_index_observations.py` (E1), `0062_scenario_parameters_and_loss_events.py` (scenarios), `0063_causal_graph_and_scenario_builds.py` (the builder), `0064_parameter_distributions_and_simulation_results.py` (step 7b), `0065_financial_validity_cards_and_receipts.py` (step 8), `0066_scenario_fingerprint_unavailable.py` (step 8's follow-up: the fingerprint at build), `0067_simulation_charts.py` (step 6) |
| Tests | `tests/test_economics_engine.py`, `tests/test_economics_money.py`, `tests/test_economics_scenarios.py`, `tests/test_economics_known_answers.py` and `tests/test_economics_templates.py` (no database), `tests/test_economics_records.py`, `tests/test_economics_scenario_records.py` and `tests/test_economics_builder.py`; step 8: `tests/test_economics_sensitivity_and_grade.py` (no database) and `tests/test_economics_validity_card.py`; step 6: `tests/test_economics_report.py` |
| mythos-core | `104fdc9` or later: `mythos_core.currency` (Mythos-Core#49) |
| Data in these phases | committed fixture snapshots only, SYNTHETIC TEST DATA in E1 (section 13); no live feed |

The package is a subpackage of the installed `assurance` app, not an app of its
own: its models are registered by one import line in `assurance/models.py` and
migrate with the rest of `assurance`. The pure core imports no Django, and of
mythos-core only its currency table; a test imports it in a fresh interpreter
with Django and every other part of mythos-core poisoned.

Out of scope, and added by later steps: running the distributions and the
sampler of section 23 for a scenario (step 7b); every endpoint but the customer
parameter set's, the scenario builder's and step 6's (section 27); feeds and their
adapters; source disagreement.
Building and verifying the signed Financial Exposure Receipt
(`mythos_core.exposure_receipt`, pinned since E1) is MVP step 8's (section 26).

## 2. Safety

No economics code is on any stop, pause, stand-down, terminate or revoke path, or
on a scan's Stop. Nothing in this package refuses, delays or holds back a stop,
and no stop reads or waits for an economics record.

Two writes reach these tables from outside economics, and neither can be held
back by them:

1. **Removing an operator, which is a stop** (`accounts:user-detail` `DELETE` in
   `safety.stops`). It sets every economics account column the operator is named
   in to NULL: `recorded_by`, `author`, `reviewer`, `requested_by` and `approver`.
   The usernames written with the rows stay, so attribution outlives the account.
2. **Deleting a deployment** (no route does this today: the admin, and later the
   customer exit). It cascades away the deployment's sources and scenarios, and
   their reviews, overrides and approvals, and the FX and cost-index observations
   of its sources (E1), and its customer parameter sets, every financial
   parameter, and the loss events and components of its scenarios (the scenario
   step).

Django runs both through each model's base manager, which is Django's plain
manager: the append-only refusals are not on that path, and `Meta.base_manager_name`
is never set on these models (a test pins it). Nor can a database constraint
refuse either write: a delete violates none, and a NULL account satisfies every
constraint that names an account column (the one-approval-each constraint leaves
NULL approvers out, and no check constraint names an account). The tests that pin
them are `test_removing_an_operator_is_never_held_back_by_economics_rows`, which
removes an operator named in every role through the real route and reads `204`,
and `test_the_records_go_with_their_deployment`, both in
`tests/test_economics_records.py`. The E1 observations name no account, so
removing an operator never writes them
(`test_removing_an_operator_who_registered_a_snapshot_is_never_held_back`), and
they go with their source and its deployment
(`test_a_tenants_snapshot_goes_with_its_deployment`). A customer parameter set
names its author as a scenario does, and removing that operator answers `204`
through the real route, nulls the account and keeps the name
(`test_removing_an_operator_is_never_held_back_by_a_parameter_set`); the scenario
records go with their deployment (`test_the_records_go_with_their_deployment` in
`tests/test_economics_scenario_records.py`). Neither a financial parameter, a loss
event nor a loss component has an account column.

The package is off every stop path in the other direction too. Two
first-party modules import `assurance.economics`: `assurance/models.py`, to
register its models, and `assurance/urls.py`, to mount its two route modules,
`assurance.economics.api`, the customer parameter-set routes (section 19), and
`assurance.economics.scenario_api`, the scenario builder's (section 24), each in a
guard of its own; `tests/test_economics_engine.py` fails if anything else imports
it. The builder and its template module are imported by that route module only,
never on Django's load path, so a fault in either leaves only the builder's routes
unserved (`test_a_builder_fault_never_takes_down_a_stop`). None of those routes is a
stop: both are classified in `safety.stops.NOT_STOPS`, the stop
tripwire (`tests/test_no_control_holds_back_a_stop.py`) holds them there, and
`test_no_economics_route_is_a_stop` pins that none is in the stop set or rides its
exemption. The write is accounted for as one that cannot move the decision
(`tests/test_every_write_route_keeps_the_decision_current.py`): it writes nothing
the decision reads. `assurance/urls.py` imports the route module GUARDED: the
root URLconf imports `assurance/urls.py`, so an import that raised there would take
the URLconf down, and every route with it -- the scan's Stop, every other stop, and
the URL check that `manage.py check` and `deliver_owed_stops` run first. A route
module that does not import is logged and its routes are not served; nothing else
changes (`test_the_economics_routes_are_imported_guarded`, read off the source).
A later step that serves more adds its route module to the import test, and that
module is never one the stop lane (`safety.stops`) judges. An economics failure is
never a reason to refuse anything outside economics.

That includes a currency table that is not the pinned one (section 5), and one
that cannot be imported at all. Django imports the economics models, and through
them the money engine and its currency adapter, when it loads `assurance.models`,
so anything the adapter did at import that could fail -- importing core's module,
which reads core's table file, or checking the pin -- would take `django.setup()`
down, and every route with it, every stop among them. The adapter therefore
imports no part of mythos-core and checks nothing at import. On the first
economics use it imports core's module -- a failure is logged and recorded as
`mythos_core.currency cannot be imported`, never raised past it -- and checks the
pin once, recording the result; every economics use refuses with
`CurrencyTableInvalid` (core's class, or a local one when core's module will not
import) while either holds. No other module the models import does work at import
that reads the environment: the vocabularies, the formula catalogue and the
parameter-set schema are built from constants.

Three fresh pytest runs, each breaking economics before Django loads, hold this:

| Fault | Plugin | Test |
|---|---|---|
| one entry of core's table changed | `tests/economics_mismatched_core.py` | `test_a_changed_core_table_never_takes_down_the_scan_stop` (`tests/economics_mismatched_core_cases.py`) |
| the route module does not import | `tests/economics_broken_api.py` | `test_an_economics_fault_never_takes_down_a_stop` (`tests/economics_fault_cases.py`) |
| `mythos_core.currency` does not import | `tests/economics_missing_core.py` | the same |

Under each, Django loads, the scan's Stop route resolves, answers (202) and saves
the Stop, and economics use refuses. Under the last two, `deliver_owed_stops` also
runs the system checks, the URL check among them, and reaches its handler, and
`manage.py check` passes; the parameter-set write answers 503 while the table
cannot be read, and records nothing.

## 3. Calculation policy

Every later step computes under these rules. A step that cannot follow one says
so and does not compute. Sections 11 and 12 say how phase E1 holds them for
money, FX and cost indices.

1. **Decimal money only.** An amount is a `Decimal` with its ISO 4217 code beside
   it, never a float, and the currency is never inferred from a locale. The
   original amount and currency are never overwritten: a converted value is a new
   value with its conversion path recorded.
2. **Minor units are for display.** Calculation runs at higher precision; a value
   is rounded to its currency's minor unit only when shown (section 5).
3. **The normalization order.** A historical amount is converted in this order:
   native amount, then event-date FX into the base currency, then the cost index to the valuation date, then valuation-date FX into the reporting currency.
   Exchange-rate change and time-value change are never mixed in one step.
4. **A missing rate is never interpolated silently.** With no rate for the date
   the policy asks for, the conversion is unavailable and says so. Where a
   scenario's policy allows an estimated rate, it is marked as estimated, the
   rule used (last official reference rate, licensed current rate) is recorded,
   and the scenario's confidence is reduced. A weekend or holiday rule is recorded
   in the same way.
5. **Market-value loss is never added to cash loss.** A share-price or
   market-capitalisation reaction is reported separately, when public-company
   analysis is enabled at all, and is never added to cash loss or to any loss
   family's total. It is not a loss family (section 4.1).
6. **Ranges, never an exact cost.** Results are ranges (P10, P50, P90, mean) with a
   confidence grade, its reason, the sources and the assumptions. Currency
   uncertainty is kept separate from scenario uncertainty.
7. **Every figure has a source.** A parameter carries its `source_type`; a source
   carries its license class, trust tier and snapshot hash. A production run never
   reads an `unreviewed` source, nor one still trusted as `unverified` (section 7).
8. **No legal, accounting, underwriting or materiality decision** is made for the
   customer. A regulatory penalty is modelled only where legally grounded, as a
   range for decision support.

## 4. Vocabularies

Each value below is a stable code: what a stored row, a fixture or a report
carries. A code is never renamed or reused; a change is a new code. The codes are
pinned by `tests/test_economics_engine.py`.

### 4.1 Loss families (`engine/taxonomy.py`)

| Code | Family | Examples |
|---|---|---|
| `direct_financial` | Direct financial loss | Fraud, theft, unauthorized transfer, erroneous disbursement |
| `business_interruption` | Business interruption | Lost revenue or margin, missed transactions, degraded service |
| `incident_response` | Incident response | Forensics, external responders, war room, communications |
| `recovery` | Recovery | Restore, rebuild, reissue credentials, infrastructure replacement |
| `legal` | Legal | External counsel, discovery, litigation, settlement defense |
| `regulatory_compliance` | Regulatory and compliance | Investigation, mandatory remediation, penalties where legally grounded |
| `notification` | Notification | Customer and regulator notices, call center, monitoring services |
| `customer_restitution` | Customer restitution | Credits, reimbursements, identity protection, reversed fees |
| `contractual` | Contractual | SLA credits, indemnification, partner claims |
| `data_and_ip` | Data and intellectual property | Trade secrets, model assets, proprietary data, training corpus |
| `customer_loss` | Customer loss | Churn, reduced acquisition, lost recurring margin |
| `third_party_downstream` | Third-party and downstream | Vendor remediation, partner losses, pass-through liability |
| `insurance` | Insurance | Deductible, uninsured portion, premium impact |
| `remediation_investment` | Remediation investment | Engineering, controls, licenses, operational change |
| `physical_operational` | Physical and operational | Equipment, fleet, plant, cyber-physical downtime |

### 4.2 Source types (`engine/provenance.py`)

What one parameter rests on: `CUSTOMER_PROVIDED`, `MYTHOS_OBSERVED`, `CALCULATED`,
`OFFICIAL_PUBLIC`, `LICENSED_MARKET`, `INDUSTRY_BENCHMARK`, `EXPERT_ESTIMATE`,
`UNKNOWN`. An industry benchmark is a prior or context, never customer-specific
truth.

### 4.3 Confidence grades (`engine/confidence.py`)

`A` (evidence rich), `B` (supported), `C` (indicative), `D` (exploratory) and
`Unknown`: Mythos cannot responsibly quantify the scenario, and says so rather
than printing a number. A grade is always shown with its reason and the range.

### 4.4 License classes (`engine/provenance.py`)

| Code | Meaning | Production run |
|---|---|---|
| `unreviewed` | nobody has reviewed the provider's terms (the default) | refused |
| `open` | reviewed: storing, deriving and redistributing are allowed | allowed |
| `restricted` | reviewed: storing and deriving allowed, not redistributing raw data | allowed |
| `licensed` | reviewed: a paid license governs use, on its recorded terms | allowed |
| `customer` | the customer's own data, on the engagement's terms | allowed |

Each production data source needs its own licensing review before its adapter
lands (owner exception 9).

### 4.5 Trust tiers (`engine/provenance.py`)

Strongest first: `authoritative` (the official publisher), `customer` (the
customer's own records), `licensed_vendor` (a commercial aggregator), `benchmark`
(an industry study or survey), `unverified` (the default: nothing yet establishes
how reliable it is).

A production run never relies on a source still trusted as `unverified`
(`source_unverified`, sections 6 and 7; the owner's decision of 12 Oct 2026, before
the first customer run). A run for a deployment recorded as `dev` or `staging` is not
a production run, and may.

## 5. The currency table

`mythos_core.currency` is the one currency table for Economic Exposure
(Mythos-Core#49, pinned since E1 at `104fdc9`). Phase E0 carried a copy of its
own, `assurance/economics/engine/data/iso4217.json`; core's table was made from
that copy entry for entry, and E1 deleted the copy and its loader.
`engine/currency.py` is now a thin adapter: it adds no entry, changes none, and
every name it exports is core's own object. Each entry has:

| Field | Meaning |
|---|---|
| `code` | the ISO 4217 alphabetic code, three capital letters, read exactly as written (`usd` is unknown) |
| `name` | the English name the list gives |
| `minor_units` | the exponent: 0 for JPY, 2 for USD, 3 for KWD; null where ISO 4217 assigns none (precious metals, bond-market units, the SDR, XTS, XXX) |
| `status` | `active` (in List One) or `retired` (in List Three only) |
| `successor` | for a retired code, the code that replaced it (HRK to EUR); null for an active one. It says which currency replaced it, never at what rate |

A code is reportable when it is active and has a minor unit. A retired code, and
one with no minor unit, is in the table so that it is known, and is refused as a
base or reporting currency with core's code `currency_retired`; a code the table
does not hold is `currency_unknown`, exactly as `mythos_core.exposure_receipt`
refuses them (section 11).

Two pins hold the table, and a core bump that changes it fails until they move in
the same reviewed change:

- **The entries.** The SHA-256 of the canonical JSON of the 216 entries
  (`mythos_core.currency.entries_digest`) is
  `00cb16d39eea4ed912c1f8fb9d43b58e19d96328090a3ad766f9cf03a868038a`, the value
  #141's copy had. `tests/test_economics_engine.py` pins the same value. The
  adapter checks, on the first economics use and never at import, whether core's
  table is the pinned one, and records the result: every economics USE of the
  table -- `currency()`, `minor_units()`, `current_successor()`,
  `reporting_refusal()`, the table names, and through them every `Money`, rate
  and policy -- raises `CurrencyTableInvalid` while it is not (section 2).
- **The file.** core pins the SHA-256 of its file's bytes, entries and `source`
  and `review` records together:
  `b23e144243e33946633529178e494ce7a43ef332408a3fd4271eceeefeaa2f9a`. The test
  pins it too, as #141's whole-document digest did, since what the table says
  about where its entries came from and how far they are checked is reviewed data
  as well.

The table records its own source (ISO 4217 List One and List Three, maintained by
SIX Financial Information as the ISO 4217 Maintenance Agency), how it was made,
and its review state. It was transcribed rather than generated from the
published files, because the build environment could not download them, and
cross-checked against two independent derivations of the standard: the active
codes and names against Debian iso-codes 4.16.0, and every entry's minor unit
against OpenJDK 21.0.10's `java.util.Currency`, which carries the historic codes
too (OpenJDK lacks UYW, whose 4 is kept; ROL was corrected to OpenJDK's 0). Its
review state says the owner verifies it against the current lists before a
production run reads an entry the tests do not pin, and names the open questions.

The retired entries are the currencies the euro replaced (GRD and PTE among
them), and the redenominations whose successor is one active code.

The tests pin, against core's table, what #141 pinned against its copy: JPY 0,
USD 2, KWD 3, the retired HRK, GRD and PTE with their successor EUR, the euro's
21 predecessors, ROL 0, CLF 4, and XAU and XXX with no minor unit. #141's table
rules (a broken entry, a duplicate, a successor loop, a wrong schema) are tested
against core's loader, which the engine now reads.

## 6. Records and their permitted writers

All are `assurance` models in `assurance/economics/models.py`. Every one is
append-only: a recorded row is never saved again or deleted, its queryset refuses
`update`, `bulk_update`, `delete` and `bulk_create`, and a new instance carrying a
recorded row's key fails rather than overwriting it. A row goes only with its
deployment, through the foreign key's cascade. These refusals guard the ORM paths
code is written against, not the table (section 10).

People are named as claim events name them: an account foreign key, nulled if the
account is removed, and a username. The username is always the account's own,
written from the account when the row is written; whatever the caller passes is
overwritten. A review, an override request and an approval need an account at
write time, so a username with no account is only ever read on a row whose account
was removed afterwards, and then still names that person.

Each coded field is checked on save and by a database check constraint: the
verdict, the license class and the trust tier. A source key, provider, dataset,
schema version and scenario title are never blank. A platform-wide source is never
licensed or trusted as `customer` data (also a check constraint). None of these
constraints touches a column a stop's write changes (section 2).

Before the scenario step no route, command or signal wrote or read any of these. The
simulation step (section 25) adds no route: its service is the only writer of a
simulation result, which step 6's simulate route calls (section 27); step 6's chart
service is the only writer of a result's chart series.
The scenario step adds one route module (section 19), the only writer of a
customer parameter set and its parameters; the builder step adds another (section
24), the only writer of a built scenario, its parameters, events, components,
effects, finding links and build record. The permitted writers below are the
ones the later steps may add, and, for the observations, the snapshot loader an
operator runs; any other writer is a defect.

| Model | Holds | Permitted writers |
|---|---|---|
| `FinancialSource` | one version of one source: `source_key`, `version` (assigned on save), provider, dataset, URL, license class, trust tier, retrieval time, snapshot hash, schema version; `deployment` empty for a platform-wide source, set for one customer's own | the fixture-snapshot loader an operator runs (MVP), and later the feed adapters, each after its licensing review; an admin may record a reviewed license class as a new version |
| `ModelInventoryEntry` | one model release: model id, version, `revision` (assigned on save), owner, intended use, limitations, retirement date | an admin, as the model-risk owner; never the engine |
| `FinancialScenario` | a scenario's identity and authorship: deployment, title, system fingerprint (the deployment's when the builder built the version, section 24.6; or none, and why, in `system_fingerprint_unavailable`), causal effect, the scenario it supersedes, its author | the scenario builder, and an admin or analyst of the deployment |
| `ScenarioReview` | one review of one scenario version: reviewer, verdict (`approved` or `returned`), note | an admin or analyst who authored no version of the scenario |
| `SensitiveOverride` | a request to override a parameter or value: subject, reason, requester | an admin or analyst |
| `OverrideApproval` | one approval of one override: approver | an admin, other than the requester; one approval per person |
| `FXObservation` (E1) | one exchange rate read from a source version's snapshot: base, quote, rate (`Decimal`), rate type, provider, `observed_at`, effective date, the source snapshot hash; linked to its `FinancialSource` | `assurance/economics/snapshots.py` `register_snapshot`, run by an operator on a committed snapshot; later a feed adapter, after its licensing review |
| `CostIndexObservation` (E1) | one published value of one cost-index series: series id, geography, category, base (`2020-03=100`), period, value (`Decimal`), vintage date; linked to its `FinancialSource` | the same |
| `CustomerParameterSet` (scenarios) | one version of one deployment's customer parameter set: `set_key`, `version` (assigned on save), the excluded insurance families, `variable_count`, `content_digest`, its author | the parameter-set API (section 19): an admin or analyst of the deployment, the roles that author a scenario; a viewer reads, never writes |
| `FinancialParameter` (scenarios) | one parameter: name, unit, `source_type`, low, base and high (decimal strings), currency, evidence reference, effective date, `fresh_until`, for a derived one, `derived_from` (the parameters it was taken across, section 24.5), and the distribution it states, if any (section 25.1); linked to exactly one scenario or one parameter-set version | a set version's parameters: the parameter-set API, with their version and only then; a scenario's: the scenario builder (section 24) |
| `LossEvent` (scenarios) | one causal loss event of a scenario: key, currency, SPINE effect, business process, trigger, correlation group | the scenario builder (section 24), through its build route |
| `LossComponent` (scenarios) | one component of one event: family, formula id and version, as-of date, the parameters it cites by input; its status and amounts are computed on save | the same |
| `ScenarioBuild` (builder) | how one scenario version was built: its parameter-set version, currency, as-of date, versions, canonical inputs and their digest, unique per deployment | the scenario builder only |
| `CausalEffect` (builder) | one effect of a built scenario version, in exactly one of its loss events (section 24.1) | the same |
| `EffectFinding` (builder) | one finding enabling one effect, and its role | the same |
| `SimulationResult` (simulation) | one Monte Carlo run of one scenario version: seed, draws, canonical inputs and their digest, every version, the record and its digest, or the refusal's code; the timing (section 25.6) | the simulation service only (section 25.7) |
| `FinancialValidityCard` (step 8) | one simulation result's Validity Card: its grade and the grade's version digest, the card and its digest, the sensitivity analysis and its digest, when it was issued; one per result (section 26.4) | the validity service only (`validity_service.issue_card`, section 26) |
| `FinancialExposureReceipt` (step 8) | one simulation result's signed receipt: the `mythos.financial-exposure-receipt/v1` document, its DSSE envelope, the key id, its card; one per result and per card (section 26.5) | the receipt service only (`receipt_service.issue_receipt`, section 26) |
| `SimulationCharts` (step 6) | one completed simulation result's chart-ready series: the exceedance curve and histogram of each line, made on the run's own draws, and their digest; one per result (section 27.4) | the chart service only (`charts_service.issue_charts`, section 27), which the simulate route calls |

The two observation models are checked on save by the engine's own contracts
(`fx.FXRate`, `cost_index.IndexPoint`), so a row is refused with the engine's code
(section 11.5) for everything the engine refuses: a float, NaN or Infinity, a zero
or negative rate or value, an unknown code or one with no minor unit, a pair of
one code, an unknown rate type, a naive instant, a malformed period, a vintage
before its period. An FX row is refused unless its snapshot hash is its source
version's own (`snapshot_hash_mismatch`), and either row unless its column holds
its value exactly (`value_precision`, section 13). A series stays one geography,
one category and one base within a source (`index_series_mismatch`). The database holds a
positive rate and value, a known rate type and a pair of two codes as check
constraints, and one row per provider, pair, rate type and date (one per series,
period and vintage) as unique constraints. Neither model has an account column.

`FinancialSource.check_usable_for_production(deployment)` raises unless a production
run for that deployment may use that version: a reviewed license class, not
synthetic, and either platform-wide or the deployment's own. `FinancialSource.objects.usable_for_production(deployment)`
returns exactly those: the reviewed platform-wide sources and the deployment's own,
never an `unreviewed` one, never a synthetic one (`FinancialSource.synthetic`, set
from a snapshot's own flag) and never another deployment's. Both read the version
as STORED: `check_usable_for_production` reads its licence class, synthetic flag,
tenant and trust tier from its row by primary key, never from the object handed in
(whose fields a caller may have changed in memory, though the row never changes), and
refuses a row that is not stored (`cross_tenant_reference`), as `snapshots.fx_book`
and `snapshots.index_book` refuse one (review of #154).

**The trust tier, for a production run** (the owner's decision of 12 Oct 2026, before
the first customer run). A production run also needs a version trusted above
`unverified`: `check_usable_for_production` refuses an `unverified` one with
`source_unverified`, after the licence, synthetic-data and tenancy refusals, and
`usable_for_production` leaves it out. The refusal names the source: its key, version
and trust tier. Which runs are production runs is decided by
`models.runs_in_production(deployment)`, from the deployment's STORED environment,
never the object handed in: a run for a deployment recorded as `dev` or `staging` is
not one and keeps the gate as it was; a run for a deployment in `production` (the
default) or `other`, for one that is not recorded, or for no deployment (`None`) is
one. A version's tier never changes; a higher tier is a new version. No route, command
or admin action records a source version yet: the only writer is the snapshot loader
an operator runs, which takes the tier from the snapshot's own document. Who may
raise a tier, and through what, is still to be decided.

`SensitiveOverride.check_in_force()` raises unless two
different people, neither the requester, have approved it. Whatever would use a
source or apply an override calls these first.

## 7. Governance rules and refusal codes

The rules are pure functions in `engine/governance.py`. Each returns nothing when
the rule holds and a code when it does not, and the models refuse a write with
that code (`EconomicsRefused.code`).

| Code | Rule |
|---|---|
| `author_reviews_own_scenario` | the reviewer authored no version of the scenario: neither the one reviewed nor any it supersedes, transitively, matched on the account and on each version's recorded username |
| `author_not_named` | a line of versions none of which names an author (all machine-drafted) is not reviewed: a person authors a version first |
| `reviewer_not_named` | a review is written by a signed-in account |
| `requester_not_named` | an override is requested by a signed-in account |
| `override_incomplete` | an override says what it overrides and why |
| `approver_not_named` | an approval is written by a signed-in account |
| `requester_approves_own_override` | the requester never approves their own override |
| `approver_already_approved` | nobody approves the same override twice (also a unique constraint) |
| `override_needs_two_approvers` | a sensitive override is in force only with two different named approvers, neither of them the requester |
| `unreviewed_license` | a production run never uses an `unreviewed` source |
| `synthetic_source` | a production run never uses a synthetic source (made-up test data), whatever its licence, and a synthetic source is never trusted above `unverified` (also a check constraint) |
| `license_class_unrecognised` | nor a source whose license class this platform does not know |
| `source_unverified` | a production run never relies on a source whose trust tier is still `unverified` (the default), nor on a tier this platform does not know; a run for a deployment recorded as `dev` or `staging` is not a production run (the owner's decision of 12 Oct 2026; section 6) |
| `snapshot_hash_malformed` | a snapshot hash is `sha256:` and 64 lowercase hex digits |
| `inventory_entry_incomplete` | an inventory entry names its model, version, owner, intended use and limitations |
| `spine_reference_malformed` | a reference into SPINE is in SPINE's form (section 8) |
| `cross_tenant_reference` | a record never points at another deployment's record, and a run never uses another deployment's source |
| `customer_source_without_tenant` | a platform-wide source is never licensed or trusted as `customer` data |
| `code_unrecognised` | a verdict, license class or trust tier is one of its codes |
| `required_field_blank` | a source key, provider, dataset, schema version or scenario title is not blank |
| `bulk_create_refused` | records are written one at a time, through the checks above |

The rules read what is stored, never what a caller's in-memory object says: the
authors of a scenario's versions, an override's requester and its approvals are
read from the rows through the base manager each time.

## 8. References into SPINE

Financial records reference SPINE by its ids and never copy what they name: SPINE
remains the source of truth, and Economic Exposure keeps no shadow of it. The forms
are `engine/governance.py`'s `REFERENCE_FORMS`:

| Thing | Named by | Form |
|---|---|---|
| system state | the system fingerprint, as an assurance claim binds to it | 64 lowercase hex |
| effect | the effect digest, as the receipt names an effect | `sha256:` and 64 lowercase hex |
| claim | the claim fingerprint every version of a claim shares | 64 lowercase hex |
| node | the asset's uuid, as the edge history names it | a lowercase hyphenated UUID |

An edge is named as the authority-edge history names it: its source asset's uuid,
its kind and its target. Phase E0 stores only the system fingerprint and the
causal effect, on `FinancialScenario`; findings, claims, edges and evidence are
linked by the scenario builder.

## 9. Open FAIR

No Open FAIR conformance is claimed. The loss taxonomy, the vocabularies and the
code names are Mythos's own; they are not the Open FAIR loss forms. Economic
Exposure may use concepts compatible with FAIR's, such as the frequency and
magnitude of a loss event, without representing conformance with the Open FAIR
standards. Claiming conformance, or using those standards commercially, would need
the licensing and legal review The Open Group's terms require first.

## 10. Limitations

- **No grade, no simulation.** E1 converts and normalizes a given amount, and
  the scenario engine computes a deterministic low, base and high per component
  and per event from given parameters (sections 14 to 18); the scenario builder
  builds a scenario's events from SPINE effects and findings (section 24). Nothing
  yet assigns a confidence grade or samples a distribution for a scenario; the
  scenario engine's own limits are section 22, the probabilistic engine's section
  23.11, and the builder's section 24.9. (Superseded: step 7b samples a stored
  scenario, section 25, and step 8 grades the result, section 26.)
- **Fixture data only.** Every source in the MVP is a committed snapshot, and the
  only one committed is SYNTHETIC TEST DATA (section 13). Nothing fetches a feed,
  and nothing is current beyond its retrieval time.
- **The currency table is transcribed.** It has not yet been diffed against the
  published List One and List Three (section 5), and holds a selection of retired
  codes, not all of List Three. It carries no exchange rates and no redenomination
  factors. It is core's table now, and athena-backend reads nothing else.
- **E1's limits** are listed in section 12.7.
- **The rules sit on the records, and on one route.** The customer parameter-set
  API (section 19) enforces its role checks; no route writes any other economics
  record yet, and the permitted writers in section 6 bind the steps that add them.
- **Append-only is an ORM guard, not a table guard.** These write past the
  refusals: the base manager (`Model._base_manager`, deliberately Django's plain
  manager so the stop's writes in section 2 pass), `django.db.models.Model.save(row)`
  called past the model's own `save`, a plain `QuerySet(model)`, raw SQL, and a
  migration. No code may use them to write an economics row: review holds that
  line, and at the database only the constraints of section 6 hold. A related
  manager's `add()`, `set()`, `remove()` and `clear()` write through the base
  manager's `update` too, so they could move a recorded row to another parent, even
  another deployment's. The scenario records' foreign keys therefore have no
  reverse accessor (`related_name="+"`), so no such manager exists for them; their
  rows are read by filtering, and the deployment's cascade still reaches them. The
  E0 and E1 records still have theirs (`superseded_by`, `reviews`,
  `sensitive_overrides`, `approvals`, `financial_sources`, `financial_scenarios`,
  `fx_observations`, `cost_index_observations`), and the same write reaches them:
  a later change removes them. A parameter-set version moved past its seal is
  detected: `intact()` re-reads its rows against the count and digest it was
  recorded with (`test_a_row_moved_past_the_append_only_checks_is_detected`).
- **SPINE references are checked for form only.** A well-formed system
  fingerprint or effect digest is accepted whether or not SPINE holds it, and
  whatever deployment it belongs to. The scenario builder must resolve every
  reference within the scenario's own deployment before anything uses it.
- **Source keys are per tenant.** A deployment's source may carry the key of a
  platform-wide one, and both count versions from 1; a run names a source by key
  and deployment, never by key alone.
- **No legal, accounting, underwriting or materiality decisions**, and no
  investment advice: outputs are decision support, with their assumptions shown.

## 11. Money

Phase E1, `engine/money.py`. Pure: no Django, no database.

### 11.1 Representation

An amount is `Money(amount, currency)`: a `Decimal` and an ISO 4217 code.

- **A float is refused on entry** (`not_decimal`), and so is an int, a bool, a
  string or anything else that is not a `Decimal`: `0.1` as a float is not one
  tenth, and a figure built on it is wrong before anything is computed.
  `Money.parse("1234.56", "USD")` reads a decimal string, in one spelling only:
  `-?[0-9]+(.[0-9]+)?`, ASCII digits, no exponent, sign or whitespace (section
  13). A multiplier is a `Decimal` too (`money * 1.5` is refused).
- NaN and Infinity, signalling or quiet, are refused (`not_finite`).
- The currency is a code the table holds (`currency_unknown`) that has a minor
  unit (`currency_retired`, core's code for a code no amount is written in). A
  retired code with a minor unit is a valid native amount (a 1999 invoice in
  DEM), never a base or reporting currency.
- A `Money` is frozen. Converting or indexing one makes a new one.

### 11.2 Precision

Arithmetic runs at 60 significant digits (`decimal.Context(prec=60)`), rounding
`ROUND_HALF_EVEN`, with an invalid operation, a division by zero and an overflow
raised (`out_of_range`), never carried on as NaN or Infinity. Addition,
subtraction and multiplication of values with fewer digits than that are exact. A
division (an inverted quote, an index ratio, an interpolation weight) is rounded
at the 60th significant digit, which for any amount below 10^15 is beyond the
40th decimal place. Nothing is rounded to the minor unit while it is computed.

### 11.3 Display

A value is rounded to its currency's minor unit only to be shown
(`Money.display_amount()`, `Money.display()`), with `ROUND_HALF_EVEN` (banker's
rounding: a tie goes to the even digit). 0.125 USD shows as 0.12 and 0.135 as
0.14; 2.5 JPY as 2 and 3.5 as 4; 1.0005 KWD as 1.000 and 1.0015 as 1.002. The
mode does not bias a column of rounded figures up or down. Display returns a value
to show, never a `Money`: a shown figure is not computed with again. Three
half-cents summed at full precision show as 0.02 USD; rounded first, each would
show as 0.00. A zero is shown as plain zero: -0.001 USD shows as 0.00, never
-0.00, while an amount that does not round to zero keeps its sign.

### 11.4 Currencies

Two amounts in different currencies never add, subtract or compare
(`currency_mismatch`, core's code); `sum()` over `Money` is refused rather than
coerced, and `Money.total(amounts, currency)` sums amounts that are all in one
currency. An amount changes currency only by a conversion that records its rate
(section 12). The base and the reporting currency of a normalization are each a
code an amount may be reported in: a retired code or one with no minor unit is
`currency_retired`, an unknown one `currency_unknown`, for exactly the codes
`mythos_core.exposure_receipt` refuses (a test runs every code in the table
through both).

### 11.5 Refusal codes

`engine/money.py`'s `REFUSALS`, raised as `MoneyRefused` by the engine and as
`EconomicsRefused` by the observation models. A code E0's governance rules also
publish keeps its meaning.

| Code | Refused |
|---|---|
| `not_decimal` | an amount, rate, index value or factor that is not a `Decimal` (in a snapshot, a JSON number rather than a decimal string) |
| `not_finite` | NaN or Infinity |
| `out_of_range` | a result too large or too small to hold at 60 digits |
| `currency_unknown` | a code the table does not hold |
| `currency_retired` | a retired code, or one with no minor unit, as a base or reporting currency; a code with no minor unit as any amount |
| `currency_mismatch` | two currencies added, subtracted or compared; an amount indexed by another currency's series; a cost index that is not the base currency's |
| `rate_not_positive` | a zero or negative exchange rate |
| `rate_type_unrecognised` | a rate type other than `reference`, `mid`, `bid` and `ask` |
| `pair_malformed` | an exchange rate whose base and quote are one code |
| `index_value_not_positive` | a zero or negative index value |
| `index_series_mismatch` | a series with two geographies, categories or bases, or a selector naming the wrong ones |
| `period_malformed` | a period that is not `YYYY-MM` |
| `date_malformed` | a date that is a datetime or text, an instant without a time zone |
| `date_inversion` | an event after its valuation date; indexing from a later date to an earlier; an index value published before its period ended (a month's value is known on its last day at the earliest) |
| `observation_duplicate` | a second rate for one provider, rate type, pair and date, or a second value for one series, period and vintage |
| `snapshot_hash_malformed` | a snapshot hash not `sha256:` and 64 lowercase hex |
| `snapshot_hash_mismatch` | an FX observation whose snapshot hash is not its source version's |
| `snapshot_malformed` | a snapshot document that breaks its schema (section 13) |
| `required_field_blank` | a blank provider, series id, geography or category |
| `policy_invalid` | a policy naming a rule, rate type, provider or limit the engine does not have |
| `value_precision` | a value its database column cannot hold exactly (section 13) |

## 12. FX, cost indices and normalization

Phase E1, `engine/fx.py`, `engine/cost_index.py` and `engine/normalization.py`.
Every function returns its value AND its provenance, or an explicit
`unavailable`; none returns a bare number.

### 12.1 FX observations

An observation (`fx.FXRate`, stored as `FXObservation`) is quoted
`1 base = rate quote`: an EUR/USD rate of 1.0850 means one euro buys 1.0850
dollars. It carries its rate type -- `reference` (an official fixing: an
informational average, not a price anyone dealt at), `mid`, `bid` or `ask` -- its
provider, when it was observed, the date it is the rate for, and the hash of the
snapshot it was read from. A rate is a positive `Decimal`.

### 12.2 The conversion policy

`fx.convert(amount, to, on, book, policy)` changes an amount's currency on a
date. `fx.FXPolicy`:

| Field | Default | Rule |
|---|---|---|
| `providers` | (required) | tried in order, strongest first: a tenant-required provider, an official reference provider, a licensed market fallback (section 19 of the owner's specification). None with a rate: `unavailable` |
| `rate_types` | `reference`, `mid` | within each provider, the rate types accepted, in order |
| `weekend_holiday_rule` | `last_official_rate` | on a day the provider does not publish (Saturday, Sunday, or a holiday in its calendar), the last official rate: its last publication day's, at most 31 days back (`fx.MAX_NON_PUBLICATION_RUN`; further is `rate_missing`). `none` turns the rule off |
| `missing_rate` | `unavailable` | a day the provider publishes on with no rate is missing: `unavailable`, or with `interpolate`, an estimate |
| `max_interpolation_gap_days` | 7 | an estimate's two observations are no further apart |
| `freshness_days` | 4 | a rate older than this for the day it is used for is flagged stale |

- **Reversed quotes.** A rate quoted the other way round (USD to EUR read from an
  EUR/USD observation) is inverted. The step records `inverted`, the rate as
  quoted, and the factor applied. A pair quoted both ways uses the direct quote.
- **Weekends and holidays.** The step records the rule `last_official_rate`, the
  date asked for and the date of the rate used. Easter Monday walks back over
  Easter Sunday, Saturday and Good Friday to Maundy Thursday when the provider's
  calendar lists the two holidays.
- **A missing rate is unavailable.** A day the provider publishes on with no rate
  is never filled from the day before (that is the weekend rule, and it is not a
  weekend), and is never interpolated unless the policy says `interpolate`. Then
  the rate is interpolated linearly between the observations either side, by
  calendar day, the step is an estimate (`estimate: true`, rule
  `linear_interpolation`, both observations and the weight recorded) and it
  carries a confidence downgrade, `estimated_rate`. Nothing is extrapolated past
  the last observation.
- **Stale.** A rate whose age (days between the day asked for and the furthest
  observation used) exceeds `freshness_days` is flagged stale, and carries the
  downgrade `stale_rate`. Any step may be the stale or estimated one -- the
  event-date step or the valuation-date step -- and the normalization's
  `estimate`, `stale` and downgrades read every step.
- **Same currency.** No conversion: the rule `same_currency`, factor 1.
- **Round trip.** Through one rate, USD to EUR and back returns the amount to
  within 1E-50, relative (`fx.ROUND_TRIP_TOLERANCE`), and exactly at display.

The rules a step records are `same_currency`, `exact`, `last_official_rate` and
`linear_interpolation`.

### 12.3 Cost indices

An index value (`cost_index.IndexPoint`, stored as `CostIndexObservation`) is one
published value of one series for one calendar month, in one vintage: series id,
geography, category, base, period (`YYYY-MM`), value, vintage date and snapshot
hash. A series is one geography, one category and one base: the base
(`2020-03=100`) is what its values are expressed relative to, and a book or a
source whose series mixes bases is refused (`index_series_mismatch`), so a
ratio's two values always share one. A series rebased by its publisher is a new
series; dividing a value on the new base by one on the old would read a rebase as
inflation or deflation. An `IndexSelector` names the series, its geography,
category and base, and the currency its prices are in.

`cost_index.index(amount, from_date, to_date, book, selector)` multiplies an amount
by the series' value for `to_date`'s month over its value for `from_date`'s month:
the ratio is computed once, at 60 significant digits, recorded, and the output is
the input times that recorded ratio, so each step of the chain reproduces from
what it lists (an FX step likewise: input times factor).
An amount in another currency than the series' is refused (`currency_mismatch`).
Each month's value is the latest vintage published on or before the as-of date
(the valuation date), and the step records which; nothing published after it is
read. A month's value is published no earlier than the month's last day: a vintage
dated inside its own month is refused (`date_inversion`), so no valuation reads
prices from its own future. The valuation month's value is therefore available
only from its last day; before that, a policy that allows a lag reads the latest
published month, flagged stale. The event month's value is that
month's or `unavailable`. The valuation month's may be the latest published month
within `index_max_lag_months` of it (default 0): the rule is then
`latest_published_period` rather than `exact_period`, the lag is recorded, and the
step is flagged stale with the downgrade `stale_index`. Nothing is interpolated.

### 12.4 The normalization order

`normalization.normalize(native, event_date, valuation_date, policy, fx_book,
index_book)` runs the four steps of section 3, in one fixed order
(`normalization.ORDER`):

1. the native amount, as recorded;
2. `event_fx`: event-date FX into the base currency;
3. `cost_index`: the base currency's cost index, event month to valuation month;
4. `valuation_fx`: valuation-date FX into the reporting currency.

A `NormalizationPolicy` names the base and reporting currencies (each reportable),
the `FXPolicy`, the base currency's `IndexSelector` (another currency's is
`currency_mismatch`) and the index lag.

Worked, on the synthetic snapshot: EUR 1,000.00 on 2020-03-02, base USD, reported
in EUR on 2026-09-30. 1,000 x 1.1000 = USD 1,100 at the event date's rate;
x 125.000 / 100.000 (September 2026's value, published on 2026-09-30, the last
day of the month and the valuation date) = USD 1,375 at the valuation date's
prices; / 1.0500 (an EUR/USD rate, inverted) = EUR 1,309.52.

Swapping the steps gives a different, wrong answer. Indexing first applies the
base currency's inflation to an amount in another currency and then prices a
historical cost at the valuation date's exchange rate: EUR 1,000 x 1.25 x 1.05 /
1.05 = EUR 1,250.00. The engine never does it: the index step refuses an amount
that is not in the series' currency. `tests/test_economics_money.py` computes both
and shows they differ.

### 12.5 Unavailable, estimates and downgrades

A normalization is `normalized` or `unavailable`. Unavailable names the step that
had nothing to go on, its reason, and what it looked for, and carries the steps
done before it; its value is none, never a guess.

| Reason | Meaning |
|---|---|
| `rate_missing` | no provider in the policy has a rate for the day (or its last official rate), and no estimate is allowed or possible |
| `index_missing` | no value of the series for the month, in any vintage published by the as-of date, within the lag allowed |

| Downgrade | When |
|---|---|
| `estimated_rate` | a rate was interpolated because the policy allowed it |
| `stale_rate` | a rate was older than the freshness limit |
| `stale_index` | the valuation month's index was not published, and an earlier month was used |

Each downgrade lowers a scenario's confidence grade one step
(`Normalization.graded`, `confidence.downgraded`): A to B, B to C, C to D, never
below D; `Unknown` stays `Unknown`. The original native amount and currency are
never overwritten: the result holds the very `Money` it was given, and the first
step's input is that object.

### 12.6 The provenance chain

`Normalization.as_dict()` is the record. Every value in it is a string, a bool, an
integer, null, a list or an object: no float. Decimals are written in one spelling
(plain notation, no exponent, no trailing zeros), so a rate read from the snapshot
and the same rate read back from its column are written alike. Abridged:

```json
{"status": "normalized",
 "native": {"amount": "1000", "currency": "EUR"},
 "event_date": "2020-03-02", "valuation_date": "2026-09-30",
 "base_currency": "USD", "reporting_currency": "EUR",
 "order": ["event_fx", "cost_index", "valuation_fx"],
 "value": {"amount": "1309.52380952380952380952380952380952380952380952380952380952", "currency": "EUR"},
 "display": "1309.52 EUR",
 "arithmetic": "Decimal, 60 significant digits, ROUND_HALF_EVEN",
 "display_rounding": "ROUND_HALF_EVEN to the reporting currency's minor unit, for display only",
 "estimate": false, "stale": false, "confidence_downgrades": [], "unavailable": null,
 "policy": {"base_currency": "USD", "reporting_currency": "EUR", "fx": {"...": "..."}, "index": {"...": "..."}},
 "chain": [
  {"step": "event_fx", "from": "EUR", "to": "USD", "requested_date": "2020-03-02",
   "rule": "exact", "provider": "SYNTHETIC-REF", "rate_type": "reference", "direction": "direct",
   "rate_date": "2020-03-02", "quoted_rate": "1.1", "factor": "1.1", "interpolation_weight": null,
   "age_days": 0, "stale": false, "estimate": false, "downgrades": [],
   "observations": [{"provider": "SYNTHETIC-REF", "base": "EUR", "quote": "USD", "rate": "1.1",
                     "rate_type": "reference", "effective_date": "2020-03-02",
                     "observed_at": "2020-03-02T15:00:00+00:00",
                     "source_snapshot_hash": "sha256:e719...8b90f",
                     "source_key": "synthetic-fx-and-cost-index", "source_version": 1}],
   "input": {"amount": "1000", "currency": "EUR"}, "output": {"amount": "1100", "currency": "USD"}},
  {"step": "cost_index", "series_id": "SYN-CPI-US", "geography": "US", "category": "...", "currency": "USD",
   "from_date": "2020-03-02", "to_date": "2026-09-30", "from_period": "2020-03", "to_period": "2026-09",
   "period_used": "2026-09", "as_of": "2026-09-30", "rule": "exact_period", "lag_months": 0,
   "ratio": "1.25", "stale": false, "estimate": false, "downgrades": [],
   "observations": [{"series_id": "SYN-CPI-US", "period": "2020-03", "value": "100", "vintage_date": "2020-04-10",
                     "source_snapshot_hash": "sha256:e719...8b90f", "...": "..."},
                    {"series_id": "SYN-CPI-US", "period": "2026-09", "value": "125", "vintage_date": "2026-09-30",
                     "...": "..."}],
   "input": {"amount": "1100", "currency": "USD"}, "output": {"amount": "1375", "currency": "USD"}},
  {"step": "valuation_fx", "from": "USD", "to": "EUR", "rule": "exact", "direction": "inverted",
   "quoted_rate": "1.05", "factor": "0.952380952380952380952380952380952380952380952380952380952381",
   "...": "..."}]}
```

Each step's output is the next step's input, and the last step's output is the
value. Every rate and index used is in the chain with its provider (or series),
date, rate type (or vintage), snapshot hash and source version.

### 12.7 Limitations of E1

- **No triangulation.** A pair with no rate either way (EUR to JPY, with only
  EUR/USD and USD/JPY in the book) is unavailable; it is never crossed through a
  third currency.
- **No holiday calendar is stored.** A provider's holidays are read from the
  snapshot file (`calendars`), and no model holds them yet: a book built from the
  database without them treats a holiday as a publication day, so a rate missing
  on it is unavailable (the safe direction: never filled in).
- **No source disagreement.** The first provider in the policy with a rate is
  used; two providers that disagree are not compared, and nothing surfaces the
  conflict yet (section 27 of the owner's specification; a later step).
- **Executable rates are not modelled.** Bid and ask are rate types a policy may
  ask for; nothing chooses the side of a trade.
- **Monthly indices only.** A series is a value per calendar month; an index is
  never interpolated within or between months.
- **The rounding mode is the engine's.** `ROUND_HALF_EVEN` for display; a customer
  whose books round half up sees a cent's difference on an exact tie.
- **Unit checks are by currency and series.** A cost index is tied to the
  currency its policy says it prices; nothing checks that a geography uses that
  currency.

## 13. Observation data and the synthetic snapshot

Phase E1 reads no feed. Every rate and index value comes from a committed snapshot
file, and a snapshot's identity is `sha256:` and the SHA-256 of its bytes: every
observation read from it carries that hash, and the `FinancialSource` version it
is registered as records it. An edit to a snapshot is a new hash, so a new source
version.

`assurance/economics/snapshots/synthetic-fx-and-cost-index-v1.json` is the one
committed snapshot. It is SYNTHETIC TEST DATA: not real exchange rates and not a
real price index. Every number in it was made up for tests, and none is a source
for a customer figure. It says so in its `label`, in its source's `dataset`, in
its providers' names (`SYNTHETIC-REF`, a reference publisher; `SYNTHETIC-MKT`, a
market with bid, mid and ask) and in its series' category. Its hash is
`sha256:e719dc303cf8eb9e2c72bc80d0261ddf4fdac810d59ebcb5472f09075c48b90f`, pinned
by `tests/test_economics_money.py` and `tests/test_economics_records.py`, and it is
registered as a `FinancialSource` (`source_key` `synthetic-fx-and-cost-index`,
platform-wide) with licence class `open` and trust tier `unverified`: the data is
Mythos's own to redistribute, and made-up numbers are never trusted above
unverified (the snapshot parser refuses a synthetic snapshot that claims more).

It holds 18 FX observations (EUR/USD, USD/JPY and USD/KWD on dates around
2020-03-02, Easter 2020 and 2026-09-30, a missing EUR/USD Wednesday on
2020-03-04, a missing USD/JPY day on 2026-09-30 between its neighbours, and the
market's rates), a calendar with SYNTHETIC-REF's two Easter holidays, and 7 index
values on the base `2020-03=100` (`SYN-CPI-US`, with a revised vintage for
2026-09 published after the valuation date, and `SYN-HICP-EA`). Every index
vintage is dated no earlier than the last day of its month.

The document (schema `mythos.economics.observation-snapshot/v1`, `engine/snapshot.py`)
has exactly `schema`, `label`, `synthetic`, `source`, `calendars`, `fx` and
`cost_index`. Every rate and value is a decimal string in one spelling,
`-?[0-9]+(\.[0-9]+)?`: a JSON number is refused (`not_decimal`), because a reader
that parses it as a float has already changed it, and so is a string `Decimal()`
alone would read -- underscores, surrounding whitespace, an exponent, a plus sign,
`NaN`, digits of another script. `Money.parse` reads the same spelling. A key that
appears twice in one object (two readers could keep different ones under one
hash), a bare `NaN` or `Infinity`, and any other broken document are
`snapshot_malformed`.

`snapshots.register_snapshot(path)` writes, in one transaction, the source version
and every observation, each through its model's checks; a file already registered
under its hash is returned, not written again. `snapshots.fx_book(sources,
deployment=...)` and `snapshots.index_book(sources, deployment=...)` read stored
observations back into the engine for a run of that deployment: every source must
be platform-wide or the deployment's own, as stored (`None` is a run for no
deployment: platform-wide only), and any other is refused
(`cross_tenant_reference`). A test shows the normalization from the rows equals
the one from the file.

Django keeps a decimal on SQLite, this service's database, as a float rounded to
15 significant digits. So every decimal column holds at most 15 digits -- a rate
up to 999,999.999999999 (9 after the point), an index value up to
999,999,999.999999 (6 after the point) -- and a value a column cannot hold
exactly is refused (`value_precision`), never rounded to fit. The engine itself
has no such limit.

**Kept out of production.** The synthetic snapshot is licensed `open`, a reviewed
class, so a licence-only gate would have let a production run read it. It is
registered with `FinancialSource.synthetic` set from its own `synthetic` flag, and
a synthetic source is refused by `check_usable_for_production` and left out of
`usable_for_production` whatever its licence (`synthetic_source`), and is never
trusted above `unverified` (refused on save, and the check constraint
`ck_econ_source_synthetic_unverified`). Whether a production run should also
refuse every `unverified` source, synthetic or not, was the owner's decision: on 12
Oct 2026, before the first customer run, the owner decided it does
(`source_unverified`, sections 6 and 7).

## 14. Parameters and units

The scenario engine (MVP step 4), `engine/parameters.py`. Pure: no Django, no
database. A parameter is one named input to a loss formula
(`parameters.Parameter`):

| Field | Rule |
|---|---|
| `name` | not blank |
| `unit` | one of the units below (`unit_unrecognised`) |
| `source_type` | one of the eight source types of section 4.2 (`source_type_unrecognised`) |
| `low`, `base`, `high` | `low <= base <= high` (`range_inverted`); a value known exactly gives the same figure three times |
| `evidence_ref` | what the figure rests on, never blank (`evidence_ref_missing`): a questionnaire answer, an evidence id, a benchmark's citation, the person who estimated it |
| `effective_date` | the date the value holds from |
| `fresh_until` | where the source says, the last date it may be read as current; before `effective_date` is `date_inversion` |
| `parameter_id` | the stored row's id (a `FinancialParameter`'s uuid), so a component cites the very row it read |

A value is a `Decimal` only (`not_decimal`: a float or an int is refused),
finite (`not_finite`), never negative (`negative_value`: no benefit model exists
yet, so nothing reduces a loss below zero), a ratio is a fraction from 0 to 1
(`ratio_out_of_range`), and a value has at most 30 digits before its point and 20
after it as written (`value_too_long`): fifty in all, inside the 60 significant
digits of section 11, so a sum of values is exact. A longer value is refused,
never rounded, truncated, read as zero or carried into an overflow.

| Unit | Holds |
|---|---|
| `money` | an amount, in the parameter's currency |
| `money_per_unit` | an amount per one thing: per event, transaction, record, customer, notice, vendor or asset (the name and evidence say which) |
| `money_per_hour` | an amount per hour: a loaded labor rate, revenue or margin per hour |
| `money_per_year` | an amount per year: annual revenue, an annual license, a yearly premium increase |
| `count` | a number of things, possibly an expected, fractional number |
| `count_per_day` | a number of things per day |
| `ratio` | a fraction from 0 to 1 |
| `hours`, `days`, `years` | a duration |

A money unit holds three `Money` in one currency (`currency_mismatch`
otherwise); a quantity unit holds three `Decimal`. A `Money` given for a
quantity, or a `Decimal` for money, is `unit_mismatch`, and so is a parameter
bound to a formula input, or written to a parameter-set variable, that takes
another unit. Nothing converts one unit into another: hours are never read as
days, and an amount is normalized into the event's currency (section 12) before a
formula reads it.

A run is made as of a date. A parameter that holds only from after it is
`date_inversion`; one past its `fresh_until` is used and flagged stale on the
component that read it (`stale_inputs`).

The scenario engine's own refusal codes are `parameters.REFUSALS`, raised as
`ParameterRefused`, which is a `MoneyRefused`, so one `except` catches every
refusal of the engine; a code the money engine already publishes (section 11.5)
is raised as that engine's, with its meaning, and is never published twice.

| Code | Refused |
|---|---|
| `unit_unrecognised` | a unit that is not one of the engine's |
| `unit_mismatch` | a parameter of another unit than its formula input or parameter-set variable takes; a money unit holding a quantity or the reverse; a currency on a quantity |
| `source_type_unrecognised` | a source type that is not one of the eight |
| `evidence_ref_missing` | a parameter that names no evidence |
| `negative_value` | a negative count, duration, ratio or amount |
| `ratio_out_of_range` | a ratio above 1 |
| `value_too_long` | a value with more than 30 digits before its point or 20 after it, as written: refused, never rounded, truncated or read as zero |
| `range_inverted` | a low above its base, or a base above its high |
| `duplicate_id` | two parameters under one name or one id, two components of one id in an event, two events of one key in a scenario, a family excluded twice (a key twice in one JSON object is refused by the API's parser, 400, naming this code) |
| `formula_unknown` | a formula id and version the catalogue does not hold |
| `formula_not_for_family` | a formula asked for a family it does not compute |
| `input_unrecognised` | a parameter bound to an input the formula does not take |
| `loss_family_unrecognised` | a component family that is not one of the fifteen or `market_value`; a sublimit or exclusion of anything but a cash family |
| `insurance_applied_twice` | insurance applied to a loss already net of it, or to a component not marked gross |
| `market_value_in_cash` | a market-value component added to cash loss |
| `field_unrecognised` | a parameter-set field or variable the schema does not hold |
| `field_missing` | a parameter-set field the schema requires and does not find |
| `field_malformed` | a field of the wrong form: not an object, not a list, text longer than its column |
| `set_key_malformed` | a parameter set's key that is not 1 to 100 of `a-z`, `0-9`, `-` and `_`, starting with a letter or digit |
| `parent_required` | a financial parameter without exactly one parent |
| `parameter_set_sealed` | a parameter added to a recorded parameter-set version |
| `parameter_not_found` | a component citing a parameter that is not recorded |
| `observed_source_not_observable` | a parameter-set money entry (a variable in a money unit, or an insurance sublimit) stated as `MYTHOS_OBSERVED`: an assessment observes a rate, a count or a duration, never a money amount (also the builder's code for an effect's attribute, section 24.2) |

## 15. The formula catalogue

`engine/formulas.py`. Each formula is a named function in plain explicit form,
with a formula id and a version, recorded with every result it gives
(`formulas.CATALOGUE`, keyed by id and version). A changed formula is a new
version; an old version stays, so a recorded result is recomputed exactly.

Every input says which way it moves the loss. `increases`: a higher value never
lowers the loss (a count, a duration, a rate, a unit cost, a cap). `decreases`: a
higher value never raises it (a recovery rate: a higher recovery rate lowers
loss). **The low result is computed from the low inputs and the high from the
high inputs, in the direction each input moves the loss**: the LOW result reads
each input's low where it increases the loss and its high where it decreases it;
the HIGH result the other way round; the BASE every base. Every formula is
monotone in every input over the values a parameter may hold, so the low result
is the smallest the ranges allow and the high the largest.

In the table, `+` is `increases` and `-` is `decreases`.

| Formula | Version | Expression | Inputs (unit, direction) | Families |
|---|---|---|---|---|
| `repeat_loss` | 1 | `repeat_count x loss_per_event x (1 - recovery_rate)` | `repeat_count` (count, +); `loss_per_event` (money_per_unit, +); `recovery_rate` (ratio, -) | `direct_financial` |
| `repeat_in_window` | 1 | `transactions_per_day / 24 x window_hours x success_rate x value_per_transaction x (1 - recovery_rate)` | `transactions_per_day` (count_per_day, +); `window_hours` (hours, +); `success_rate` (ratio, +); `value_per_transaction` (money_per_unit, +); `recovery_rate` (ratio, -) | `direct_financial` |
| `interruption` | 1 | `interruption_hours x value_per_hour` | `interruption_hours` (hours, +); `value_per_hour` (money_per_hour, +): revenue or margin, its evidence says which | `business_interruption`, `physical_operational` |
| `fixed_plus_hours` | 1 | `fixed_cost + hourly_rate x hours` | `fixed_cost` (money, +); `hourly_rate` (money_per_hour, +); `hours` (hours, +) | `incident_response`, `recovery`, `legal`, `regulatory_compliance`, `remediation_investment`, `third_party_downstream`, `data_and_ip`, `physical_operational` |
| `per_affected_plus_fixed` | 1 | `affected x unit_cost + fixed_cost` | `affected` (count, +); `unit_cost` (money_per_unit, +); `fixed_cost` (money, +) | `notification`, `customer_restitution`, `third_party_downstream`, `physical_operational`, `recovery` |
| `per_affected` | 1 | `affected x amount_per_affected` | `affected` (count, +); `amount_per_affected` (money_per_unit, +) | `customer_restitution`, `notification`, `third_party_downstream` |
| `support_contacts` | 1 | `affected x contact_rate x handling_hours x loaded_rate` | `affected` (count, +); `contact_rate` (ratio, +); `handling_hours` (hours, +); `loaded_rate` (money_per_hour, +) | `notification`, `customer_restitution` |
| `capped_credit` | 1 | `min(credit_per_hour x breach_hours, contract_cap)` | `credit_per_hour` (money_per_hour, +); `breach_hours` (hours, +); `contract_cap` (money, +) | `contractual` |
| `replacement_share` | 1 | `replacement_cost x share_compromised` | `replacement_cost` (money, +); `share_compromised` (ratio, +) | `data_and_ip` |
| `churned_margin` | 1 | `customers x churn_rate x margin_per_customer_per_year x recovery_years` | `customers` (count, +); `churn_rate` (ratio, +), from `CUSTOMER_PROVIDED` data only; `margin_per_customer_per_year` (money_per_unit, +); `recovery_years` (years, +) | `customer_loss` |
| `premium_increase` | 1 | `premium_increase_per_year x years` | `premium_increase_per_year` (money_per_year, +); `years` (years, +) | `insurance` |
| `lump_sum` | 1 | `amount` | `amount` (money, +): a range given whole by its source, a quote, a benchmark or an estimate | every cash family but `customer_loss` and `insurance` |
| `share_price_reaction` | 1 | `market_capitalisation x price_decline` | `market_capitalisation` (money, +); `price_decline` (ratio, +) | `market_value` only |

The rules every formula keeps. A component is `estimated`, with a low, base and
high, or `unknown`, with none.

- **Money arithmetic only.** A formula multiplies `Money` by `Decimal` factors and
  adds `Money` to `Money` in one currency, at 60 significant digits (section 11).
  Inputs in two currencies are `currency_mismatch`.
- **Units are checked** (section 14).
- **A missing input gives an explicit unknown component, never a zero.** A
  component with an input unbound is `unknown`, with the reason `input_missing`
  and the inputs it lacks, and carries no amount at all. So is one whose input
  rests on a source the formula does not accept, `input_source_not_accepted`:
  customer loss is computed only from the customer's own churn figure (the
  owner's specification, section 31: otherwise Unknown).
- **Every result carries its provenance**: the formula id, version and
  expression, and for each input the parameter it read (its name, id, unit,
  source type, evidence and dates), which of its values the low and the high
  read, and those values. A component is always gross of insurance
  (`insurance_treatment`, `gross`).
- `market_value` is a component family outside the fifteen (section 4.1), computed
  only by `share_price_reaction`, never added to cash loss (section 16).
- The `insurance` family is computed only by `premium_increase`: a lump sum filed
  as insurance could be the deductible, which the insurance step already keeps, and
  would count it twice (`formula_not_for_family`).

## 16. Loss events, components and totals

`engine/loss.py`. A loss event (`loss.LossEvent`) is the scenario that creates a
financial consequence, and its components (`formulas.LossComponent`) are the
losses it causes. Section 6 of the owner's specification: findings are clustered
into causal loss events, and duplicate findings never create duplicate loss.

- **One id, one thing.** An event's components have distinct ids, and one
  parameter name or id denotes one parameter across the event (`duplicate_id`): a
  parameter two components read is the same parameter, never two that share a
  name.
- **One currency.** Every component of an event is in the event's currency
  (`currency_mismatch`).
- **Unknown is never zero.** The cash total of an event with an unknown cash
  component is `complete: false`: its figures are the sum of the known components
  only, a floor that reads "at least", and the unknown components are named beside
  it. It is never shown as the event's loss.
- **Market value is never cash.** A `market_value` component is reported on its
  own line, `never_added_to_cash`, and is never added to cash loss or to any
  family's total: the cash total refuses one (`market_value_in_cash`), and no
  insurance policy sees it.
- The event's low is the sum of its components' lows and its high the sum of
  their highs. Each component sits at the end of its own ranges, so a parameter
  two components read in opposite directions widens the event's range; it never
  narrows it.

`loss.assess(event, policy)` gives the gross cash loss, the loss net of
insurance when a policy is given (section 17), and the market-value line, with
every component's provenance. The arithmetic is `Decimal`, 60 significant digits,
`ROUND_HALF_EVEN`, with no seed and no sampling.

## 17. Insurance

`loss.apply_insurance(gross, policy)`. **Insurance is applied once, after the gross
components**, never to a loss already net of it and never to a component not
marked gross (`insurance_applied_twice`). An `InsurancePolicy` holds a
deductible and an aggregate limit (money parameters), per-family sublimits (money
parameters), excluded families, and optionally a waiting period (an hours
parameter), each with its provenance like any other input. Its terms are in one
currency, the loss's (`currency_mismatch`).

At each point, low, base and high:

1. the covered amount of each cash family is the sum of its known components,
   unless the family is excluded, or is `insurance` (a premium rise is the
   policy's own cost, never a loss it pays), or is `business_interruption` while
   the policy has a waiting period (below);
2. a family with a sublimit is covered up to it;
3. the recovery is `min(max(covered - deductible, 0), limit)`;
4. the retained loss is the gross cash loss less the recovery.

Each term moves the retained loss one way (`loss.TERM_DIRECTIONS`), and is read at
the end its direction gives, as a formula's inputs are: the low retained loss
reads the low deductible and the high limit.

| Term | Direction | Low retained loss reads |
|---|---|---|
| `deductible` | `increases` | its low |
| `limit` | `decreases` | its high |
| `sublimit` | `decreases` | its high |
| `waiting_period_hours` | `increases` | its low |

The retained loss is never negative: the recovery is never more than the covered
amount, which is never more than the gross loss. Insurance on an incomplete gross
loss gives a retained floor, still `complete: false`.

A policy with a waiting period does not cover business interruption at all in
this version. The engine does not apportion an outage across the waiting period,
so it takes the side that never understates the retained loss. **A policy that
states no waiting period is read the same way**: unstated is unknown, never zero,
so business interruption is not covered unless the policy states a waiting period
of zero.

**The order of the sublimit and the deductible is not the usual one, and it is
disclosed.** The engine caps each family's covered amount at its sublimit first
and then takes the deductible off the covered total (steps 2 and 3). The usual
policy wording takes the retention off the loss first and caps the payment at the
sublimit. The two differ when a family's loss exceeds its sublimit. Worked: a
notification loss of USD 300,000, a notification sublimit of USD 150,000, a
deductible of USD 100,000 and a limit of USD 1,000,000.

- The engine: covered `min(300,000, 150,000)` = 150,000; recovery
  `min(150,000 - 100,000, 1,000,000)` = 50,000; **retained USD 250,000**.
- The usual reading: `300,000 - 100,000` = 200,000 after the retention; payment
  capped at the sublimit, 150,000; **retained USD 150,000**.

The engine's order never retains less than the usual reading, so it never
understates the retained loss, which is why it is kept for now; it overstates it
by up to the deductible where a sublimit binds. Choosing the usual order is an
owner decision (section 22), and
`test_the_sublimit_is_applied_before_the_deductible_as_disclosed` pins the current
figures so a change is deliberate.

## 18. The invariants

The owner's specification, section 27, and the tests that prove each:

| Invariant | Holds by | Proven by (`tests/`) |
|---|---|---|
| `low <= base <= high` for every component, total and retained loss | each input's range is ordered, and every formula is monotone; checked on every evaluation (`InvariantBroken`, a defect, never an input's fault) | `test_economics_scenarios.py`: `test_low_base_high_are_ordered_and_never_negative`, for every formula; `test_retained_loss_is_never_negative` |
| Monotone in every input | each formula is a sum and product of non-negative inputs, `1 - ratio` and `min`; a decreasing input enters only as `1 - ratio` | `test_every_formula_is_monotone_in_every_input` (a deterministic sweep: this repository does not use hypothesis) and `test_widening_one_input_moves_only_the_end_its_direction_says`, for every formula and input; `test_retained_loss_is_monotone_in_every_term_and_every_component` |
| Non-negative | no input may be negative (no benefit model is enabled), and a ratio is at most 1 | the adversarial parameters; the ordering tests check `0 <= low` |
| Seed-free determinism | no randomness, no clock, no set-order dependence | `test_the_same_inputs_give_the_same_result_with_no_seed` (two interpreters, two hash seeds, one digest); `test_no_scenario_module_reads_a_clock_or_a_random_source` |
| A missing input is unknown, never zero | `formulas.evaluate` and `loss.Total` | `test_a_missing_input_gives_unknown_never_zero`, for every formula and input |
| Units and currencies are checked | `Parameter`, `evaluate`, `LossEvent`, `InsurancePolicy` | `test_a_parameter_of_another_unit_is_refused`, `test_money_in_two_currencies_is_refused`, for every formula |
| Insurance once, never a negative retained loss | `apply_insurance` takes a `GrossLoss` only | `test_insurance_is_applied_once`, `test_retained_loss_is_never_negative` |
| Market value never in cash | `cash_total` refuses it; `assess` reports it apart | `test_market_value_is_never_summed_into_cash` |
| The adversarial parameters: NaN, Infinity, a float, negative counts, rates above 1, unit mismatch, date inversion, duplicate ids | section 14 | `test_an_adversarial_parameter_is_refused`, `test_duplicate_ids_are_refused`, `test_a_parameter_from_after_the_runs_date_is_refused_and_a_stale_one_flagged` |

## 19. The customer parameter set and its API

A parameter set is one deployment's answers to the executive questionnaire of the
owner's specification, section 14: customer-specific data, which should dominate
an estimate wherever it exists. It is deployment-scoped and versioned, and each
version records its author. `engine/parameter_set.py` holds the schema, schema
`mythos.economics.parameter-set/v1` (`SCHEMA_VERSION`).

### 19.1 The variables

Thirty variables in nine domains (`parameter_set.VARIABLES`, `parameter_set.Domain`).
Public-market context (ticker, market capitalisation) is not a variable: it is
market value, never a cash input.

| Variable | Domain | Unit | Meaning |
|---|---|---|---|
| `annual_revenue` | `scale` | `money_per_year` | annual revenue |
| `operating_margin` | `scale` | `ratio` | operating margin, as a fraction of revenue |
| `customer_count` | `scale` | `count` | customers |
| `transactions_per_day` | `transactions` | `count_per_day` | transactions per day |
| `average_transaction_value` | `transactions` | `money_per_unit` | average transaction value |
| `maximum_transaction_value` | `transactions` | `money_per_unit` | largest transaction value |
| `recovery_rate` | `transactions` | `ratio` | share of a misdirected amount settled back or recovered |
| `customer_record_count` | `data` | `count` | customer records held |
| `regulated_record_count` | `data` | `count` | health, payment or other regulated records held |
| `retention_days` | `data` | `days` | how long records are retained |
| `revenue_per_hour` | `operations` | `money_per_hour` | revenue of the critical service per hour |
| `margin_per_hour` | `operations` | `money_per_hour` | margin of the critical service per hour |
| `recovery_time_objective_hours` | `operations` | `hours` | recovery time objective (RTO) |
| `security_responder_hourly_rate` | `labor` | `money_per_hour` | loaded hourly rate of an incident responder |
| `engineering_hourly_rate` | `labor` | `money_per_hour` | loaded hourly rate of an engineer |
| `support_agent_hourly_rate` | `labor` | `money_per_hour` | loaded hourly rate of a support or call-center agent |
| `incident_team_size` | `labor` | `count` | people on the incident team |
| `external_counsel_hourly_rate` | `legal` | `money_per_hour` | external counsel's hourly rate |
| `legal_retainer` | `legal` | `money` | external counsel's retainer |
| `notification_unit_cost` | `legal` | `money_per_unit` | cost of notifying one person |
| `notification_fixed_cost` | `legal` | `money` | fixed cost of a notification campaign |
| `critical_vendor_count` | `vendors` | `count` | critical vendors |
| `vendor_exit_cost` | `vendors` | `money_per_unit` | cost of exiting or recovering one critical vendor |
| `vendor_liability_cap` | `vendors` | `money` | contractual cap on a vendor's liability or indemnity |
| `insurance_deductible` | `insurance` | `money` | deductible or self-insured retention |
| `insurance_limit` | `insurance` | `money` | aggregate policy limit |
| `insurance_waiting_period_hours` | `insurance` | `hours` | waiting period before business interruption cover |
| `remediation_engineering_hours` | `remediation` | `hours` | engineering hours a remediation takes |
| `remediation_license_cost_per_year` | `remediation` | `money_per_year` | yearly licensing cost of a remediation |
| `remediation_duration_days` | `remediation` | `days` | days a remediation takes to implement |

Beside them, `insurance_sublimits` (a money entry per cash family, stored as a
parameter named `insurance_sublimit:` and the family) and `insurance_exclusions`
(a list of cash families). A version with a deductible and a limit states an
insurance policy (section 17); without either it states none, and nothing assumes
one.

### 19.2 The document

```json
{"variables": {
   "transactions_per_day": {"unit": "count_per_day", "low": "18000", "base": "18000", "high": "18000",
                            "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "CFO questionnaire 2026-09",
                            "effective_date": "2026-09-30"},
   "legal_retainer": {"unit": "money", "currency": "USD", "low": "50000", "base": "50000", "high": "75000",
                      "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "engagement letter",
                      "effective_date": "2026-07-01", "fresh_until": "2027-06-30"},
   "average_transaction_value": {"unit": "money_per_unit", "currency": "USD",
                                 "low": "20000", "base": "25000", "high": "32000",
                                 "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "payments ledger 2026-Q3",
                                 "effective_date": "2026-09-30",
                                 "distribution": {"id": "lognormal", "version": 1,
                                                  "params": {"mu": "10.1266", "sigma": "0.15"}}}},
 "insurance_sublimits": {"notification": {"unit": "money", "currency": "USD", "low": "150000", "...": "..."}},
 "insurance_exclusions": ["regulatory_compliance"],
 "frequency": {"unit": "count", "low": "1", "base": "2", "high": "4",
               "source_type": "INDUSTRY_BENCHMARK", "evidence_ref": "industry loss data, 2021-2025",
               "effective_date": "2026-09-30",
               "distribution": {"id": "poisson", "version": 1, "params": {"rate": "2"}}}}
```

Every entry, a variable, a sublimit or the frequency, may state the distribution it
draws from in a simulation (`distribution`, section 25.1), and the document may state
the scenario's `frequency`, events a year, which always states its count
distribution. Section 19.4 says how each is read and held to its figures.

Read exactly or refused, with the field's path in the detail. Unknown fields are
refused (`field_unrecognised`), at the top, in an entry and as a variable name;
required ones are `field_missing`; a field of the wrong JSON type is
`field_malformed`. Every entry states its unit, and a unit that is not the
schema's is `unit_mismatch`: a client that thinks transactions are counted per
hour is refused, never read as per day. A money entry states its currency, a
quantity never does. **Money follows section 13's strict decimal-string rule**: a
value is a decimal string in the one spelling `-?[0-9]+(\.[0-9]+)?`, and a JSON
number, an exponent, a sign, whitespace, an underscore or `NaN` is `not_decimal`.
Dates are `YYYY-MM-DD` (`date_malformed`). Every rule of a parameter (section 14)
holds for every entry. **A money entry is never `MYTHOS_OBSERVED`**: a variable whose
unit is money, or money per unit, hour or year, and an insurance sublimit, are the
customer's own figures (`CUSTOMER_PROVIDED`, `EXPERT_ESTIMATE` or another source that
is not an observation), and a version that states one as observed is refused whole
(`observed_source_not_observable`, the builder's code and meaning: an assessment
observes a rate, a count or a duration, never what the customer's money is). A
quantity entry may be observed.

A version's identity is its `content_digest`: `sha256:` and the SHA-256 of its
canonical JSON (sorted keys, the one decimal spelling, `schema` included), the
same whether read from the request or back from the stored rows. A stated
distribution, in its one spelling, and the frequency are part of it; a version that
states neither has the canonical document, and the digest, it had before either
could be stated, so every version recorded before step 6 stays intact.

### 19.3 The routes

Mounted under `/api/assurance/` from `assurance/economics/api.py`:

| Route | Name | Does |
|---|---|---|
| `GET deployments/<uuid>/economics/parameter-sets/<set_key>/` | `deployment-economics-parameter-set` | the current version (the highest), with every variable, its domain, unit, currency, values, source type, evidence and dates; 404 when the set has none |
| `GET deployments/<uuid>/economics/parameter-sets/<set_key>/versions/` | `deployment-economics-parameter-set-versions` | every version, newest first, without their figures: version, author, recorded time, digest, variable count; at most 200, and `truncated` says when there are more |
| `POST` the same | the same | records the next version from a document (append-only), and answers 201 with it |

- **Authentication and tenancy**, as the assurance API's: a signed-in account
  (401 otherwise); a deployment the caller cannot see is 404, whether or not it
  exists, exactly as the deployment list scopes them (admins and analysts see
  every deployment, anyone else their own).
- **Writers**: an admin or an analyst, the roles section 6 names as a scenario's
  authors; a viewer, even the deployment's owner, reads and is refused 403. The
  version's author is the signed-in account, never anything the body says. The
  reviewer separation of section 7 is unchanged: a scenario is still reviewed by
  someone who authored no version of it, and a parameter set is not reviewed in
  this version (section 22).
- **Append-only**: no route edits or deletes a version (405); a change is a new
  version, and the earlier one reads back unchanged.
- **Strict JSON**: the body is JSON only (a form is 415) and at most 64 KiB (413,
  on its declared `Content-Length` before anything reads it, and the parser never
  reads past the limit); a key twice in one object and a bare `NaN` or `Infinity`
  are refused by the parser (400). A refusal is 400 with `code` (the engine's) and
  `detail` (the field's path), and nothing is recorded.
- **Unavailable**: while economics cannot read its currency table (section 2),
  the write and the read of a version answer 503 and record nothing; the list of
  versions, which reads no amount, still answers. A version that states a
  distribution is 503 too while the probabilistic engine (or numpy) will not import,
  and records nothing; one that states none never imports it (section 19.4).
- **A race**: two versions posted at the same moment that would take one number
  are refused by the unique constraint: the later is 409 and writes nothing.
- **Not on a stop path**: both routes are in `safety.stops.NOT_STOPS`; the POST
  writes nothing the decision reads.

### 19.4 The writer of stated distributions and the frequency (MVP step 6)

Before step 6 the column existed (`FinancialParameter.distribution`, section 25.1) and
the run read it, but no route or document set it, so a customer's range could only be
refused (`no_admissible_distribution`). Step 6 gives it its writers, with one rule for
each:

| What | Written by | Stored as |
|---|---|---|
| a variable's or a sublimit's distribution | the parameter-set POST (section 19.3), the entry's `distribution` | the set row's `distribution` |
| the scenario's frequency, with its count distribution | the parameter-set POST, the document's `frequency` | a set row named `frequency`, unit `count` |
| an effect attribute's distribution | the scenario builder's POST (section 24.8), the attribute's `distribution` | the scenario row's `distribution` |

**Why these writers.** An event's parameters are written in two places, so both take a
distribution: the customer's variables by the parameter set, and an effect's attributes
by the builder (section 24.2); a derived parameter states none, and draws from its
contributors' (section 25.1, rule 5). The frequency is the parameter set's, as the
lead's brief for step 6 places it: it is the customer's figure of how often a loss
recurs, read at run time through the parameter-set version the build names, exactly as
the policy's terms are (section 25.5), and part of that version's digest and so of the
build's. It applies to every scenario built from the version; a frequency per scenario
or per template is an owner decision (section 25.10, decision 12).

**The same rules for every writer**, the routes' own: a signed-in admin or analyst
only (a viewer is 403), the author the signed-in account, append-only, strict JSON of
at most 64 KiB (413 on the declared length), refused whole with the engine's code and
nothing written. A stated distribution is read exactly (`scenario_simulation.parse_stated`:
`distribution_malformed`, `distribution_unknown`, `distribution_version_unknown`) and
kept in its one spelling (`"mu": "10.12660"` is stored `"10.1266"`); then, when its
row is checked, it is held to its row by the simulation's own test, the one a run
applies (section 25.1): built by step 7a's catalogue with all its checks
(`expert_not_allowed` for an expert range a customer's figure states), fitting its unit
(`distribution_not_for_unit`), and holding its figures (`distribution_contradicts_range`,
naming the variable and the test it failed): every stated distribution from both sides
and never on a fixed row (`distribution_on_fixed_row`), a count on any row but the
frequency included; the frequency, whose figures are values of its rate, by the rate
its count implies, a fixed rate only as a Poisson of that rate. A frequency must state
a count distribution (`field_missing` without one, `frequency_not_a_count`). Only the
fault's type is kept when the probabilistic engine will not import, for any fault
(503, nothing recorded; review round 1, NIT-2).

**Write time, build time and run time agree.** All three call one function,
`check_fits_range`, on the row as stored: the refusal a POST gives is, code and detail
word for word, the refusal a build gives a version recorded before the rule or under
an earlier floor (`builder.check_set_distributions` re-checks every distribution the
named version states, review round 1, LOW-3), and the refusal a run gives a scenario
built from it (`test_write_time_and_run_time_refusals_agree`). A build of a version
that states a distribution needs the probabilistic engine: 503 while it will not
import, and nothing built.

**The transaction only inserts.** Every check of the version and of each of its rows,
each stated distribution's test included, runs before the version's transaction
(`CustomerParameterSet.check_rows`), which then only inserts, each row exactly as it
was checked (`_insert_as_marked`; a row changed since its check is refused): on SQLite
a stop's write waits for the inserts alone, as section 24.6 has it for a build
(`test_a_versions_transaction_only_writes`). A version raced to the same number is
still stopped by the unique constraint, 409.

**Served back.** The version's GET serves each variable's and sublimit's
`distribution` (null where it states none) and the `frequency` (null where it states
none); the builder's events serve each effect attribute's.

## 20. The scenario records

`assurance/economics/models.py`, migration `0062_scenario_parameters_and_loss_events.py`.
All four are append-only like every economics record (section 6), go with their
deployment, and are checked on save with the engine's codes.

- **`CustomerParameterSet`**: `set_key` names a set within its deployment
  (`bank_prod_2026q4`, as the owner's specification's scenario request names
  one); `version` counts from 1 per deployment and key; the highest is current.
  `CustomerParameterSet.record` writes a version and its parameters in one
  transaction, refused whole or written whole; every check runs before it, and it
  only inserts (section 19.4). `variable_count` (the rows, the frequency's included) and
  `content_digest` are taken from the validated document before any row is
  written; a parameter added to a recorded version afterwards is
  `parameter_set_sealed`, and `intact()` re-reads the rows and compares their
  count and digest.
- **`FinancialParameter`**: exactly one parent, a scenario or a parameter-set
  version (`parent_required`, and the check constraint
  `ck_econ_parameter_one_parent`); one name per parent (`duplicate_id`, and a
  unique constraint); a set version's parameter is one of the schema's variables
  with its unit, a sublimit, or the frequency (a count). It may state a distribution
  (section 19.4). Its values are decimal strings in the one spelling (section 12.6),
  exact at any width where a decimal column on SQLite keeps 15 significant digits;
  `"200.000"` is stored as `"200"`. The unit and the source type are check
  constraints too.
- **`LossEvent`**: a key unique within its scenario (`duplicate_id`, and a unique
  constraint), a reportable currency, the SPINE effect in SPINE's form (checked
  for form only, section 10).
- **`LossComponent`**: its family, formula id and version, as-of date and the
  parameters it cites by input (`cited_parameters`). **Its amounts are never taken
  from the caller**: on save, its formula is evaluated from the cited parameters
  as stored, and the status, currency, low, base and high, or the unknown reason
  and the missing inputs, are written from that result. Every cited parameter is
  recorded (`parameter_not_found`) and belongs to the event's own deployment, the
  scenario's or one of the deployment's parameter sets
  (`cross_tenant_reference`). A stored component is gross (the check constraint
  `ck_econ_component_gross`); insurance is applied once, when an event is
  assessed. `LossEvent.as_engine()` recomputes every component from its rows.

Every reference is tenant-scoped: a component never cites another deployment's
parameter, a parameter's tenant is its parent's deployment, and the API reads and
writes only the deployment in its path.

## 21. Known-answer fixtures

`tests/test_economics_known_answers.py` holds the owner's specification's two
worked examples as committed tests, labelled SYNTHETIC / ILLUSTRATIVE, with every
expected figure computed by hand in the comments. They are the known-answer seeds
for Minotaur's economic-exposure tests.

- **Section 30, the bank payment agent.** 18,000 transactions a day, a 0.5 to 2.0
  hour window, 7 of 20 attempts succeeding, USD 25,000 per transfer, 70% to 95%
  recovered: direct loss USD 164,062.50 / 1,435,546.875 / 3,937,500 by
  `repeat_in_window`; with incident response (USD 80k to 250k) and the
  legal/regulatory response (USD 150k to 1.5M), the event's gross cash loss is USD
  394,062.50 / 2,425,546.875 / 5,687,500. Where the specification gives a range
  and no base, the base is the midpoint. The remediation cost is the price of the
  fix, a mitigation option (section 21 of the owner's specification), and is not a
  component of this event's loss.
- **Section 31, cross-customer data exposure.** The specification gives the
  approach and no figures, so the figures are made up and labelled so. Notification,
  support, forensics, legal and regulatory bounds give a gross cash loss of at
  least USD 239,000 / 746,250 / 2,580,000; customer loss is unknown, because its
  churn figure is a benchmark; and a policy with a USD 100,000 deductible, a USD
  1,000,000 limit, a USD 150,000 notification sublimit and regulatory excluded
  leaves at least USD 100,000 / 231,250 / 1,580,000 retained.
  `tests/test_economics_scenario_records.py` stores the same example as rows and
  reads back the same answer.

## 22. Limitations of the scenario engine, and decisions for the owner

- **Deterministic ranges, not distributions.** Low, base and high are the ends
  and the middle of the inputs' ranges, not percentiles: they are not P10, P50 and
  P90, and nothing here estimates a frequency. The probabilistic engine is a later
  step (sections 23 and 25; step 6 writes a parameter's distribution and the
  frequency, section 19.4).
- **The event's range is a box, not a joint scenario.** Summing component lows
  treats every component as at its own low at once, so a parameter two components
  read in opposite directions widens the range.
- **No benefit model.** Nothing may be negative, so nothing offsets a loss.
- **`money_per_unit` does not say per what.** A unit cost per record bound to an
  input that counts customers is not caught by the unit check; the parameter's name
  and evidence say which, and the scenario builder must bind them consistently.
- **Insurance is applied at the event's totals.** The retained loss is not
  allocated back to families; a waiting period, stated or not, removes
  business-interruption cover rather than apportioning it; coinsurance,
  per-occurrence limits and several policies are not modelled.
- **The sublimit comes before the deductible** (section 17): with a notification
  loss of USD 300,000, a USD 150,000 sublimit, a USD 100,000 deductible and a USD
  1,000,000 limit, the engine retains USD 250,000 where the usual policy reading
  retains USD 150,000. It never understates the retained loss, and overstates it
  by up to the deductible where a sublimit binds.
- **Freshness is flagged, not graded** by the scenario engine. A stale parameter is
  named on the component that read it; step 8 grades it (section 26.2: one step
  down, `stale_inputs`).
- **No regulatory penalty is predicted.** A regulatory component is a range its
  evidence must ground (section 3, rule 8); the engine adds nothing to it.
- **Categorical inputs are not in the schema.** Data classes, jurisdictions, the
  critical services and vendor names (section 14 of the owner's specification)
  are not variables yet; only figures are.
- **The parameter-set API writes no scenario records.** Scenario parameters, loss
  events and components are written by the scenario builder (section 24); the
  models hold the rules for it.
- **A parameter names its evidence as text.** `evidence_ref` is not yet a link to
  a `FinancialSource` version or a SPINE evidence id, and nothing checks that it
  resolves.
- **No generic cap or floor.** A component is capped only where its formula takes
  a cap as an input (`capped_credit`); the owner's specification's cap/floor
  column on a component is not modelled.

Decisions this version takes, which the owner may change:

1. A parameter-set version is recorded by an admin or an analyst and is not
   reviewed: the scenario that cites it is reviewed under section 7. Whether a
   set needs a reviewer of its own is open.
2. Remediation cost is a mitigation's price, never a component of the loss event
   it mitigates (the owner's specification, section 21); `remediation_investment`
   components are for remediation the incident itself forces.
3. A premium rise (`insurance` family) is never covered by the policy, and only
   `premium_increase` computes that family; a waiting period, or one the policy
   does not state, removes business-interruption cover (section 17).
4. Customer loss is computed only from `CUSTOMER_PROVIDED` churn; any other source
   gives an unknown component.
5. Where a worked example gives a range and no base, its base is the midpoint.
6. The sublimit is applied before the deductible (section 17), the side that
   never understates the retained loss; whether to change to the usual order, the
   retention off the loss first and the payment capped at the sublimit, is the
   owner's decision, recorded as open.

## 23. Distributions and simulation

Phase E2, MVP step 7a: the distribution library and the seeded Monte Carlo
sampler of the owner's specification, sections 7.1 to 7.3. It follows the
scenario engine's sections 14 to 22 (MVP step 4). Both modules are pure; step 7b
wires them to the formulas and the records (section 25), and section 23.11 says what
is still not wired.

| | |
|---|---|
| Code | `assurance/economics/engine/distributions.py` (the catalogue) and `assurance/economics/engine/simulation.py` (the sampler); no model, no migration, no route |
| Tests | `tests/test_economics_distributions.py` and `tests/test_economics_simulation.py` (no database), with the plugin `tests/economics_probabilistic_poisoned.py` |
| Dependency | numpy, `Generator(PCG64)`: `numpy==2.3.3`, the pin `requirements.txt` already had, now in `requirements-dev.txt` too (CI's set), and a test holds the two alike |

### 23.1 The catalogue

Each distribution is a frozen value whose parameters are checked when it is
built. It is built from its native parameters (form `native`) or from a form a
customer gives, and records which form and the values given. Each has a stable
id, never reused, and a version: a change to how one samples, or how its
parameters are read, is a new version. Every sample set records both
(`Distribution.record()`), with the native parameters, the form, the values given,
and the mean and variance.

| Id | Kind | Native parameters | Customer forms | Mean, variance |
|---|---|---|---|---|
| `poisson` | `frequency` | rate > 0 | | rate, rate |
| `negative_binomial` | `frequency` | size r > 0, p in (0, 1) (numpy's: failures before the r-th success) | `mean_variance`: p = m / v, r = m^2 / (v - m), refused unless v > m (`not_overdispersed`) | r(1-p)/p, r(1-p)/p^2 |
| `zero_inflated_poisson` | `frequency` | zero inflation pi in [0, 1), rate > 0 | | (1-pi) rate, (1-pi) rate (1 + pi rate) |
| `beta_binomial_rate` | `rate` | alpha, beta > 0 | `prior_and_trials`: Beta(a0, b0) prior and k successes of n trials give Beta(a0 + k, b0 + n - k); the prior defaults to Beta(1, 1) and is recorded | alpha/(alpha+beta), alpha beta / ((alpha+beta)^2 (alpha+beta+1)) |
| `lognormal` | `severity` | mu, sigma > 0 | `median_sigma`; `p10_p90`: mu = (ln P10 + ln P90)/2, sigma = (ln P90 - ln P10)/(2 z90); `median_p90`: sigma = (ln P90 - ln median)/z90; z90 = 1.2815515655446004 | exp(mu + sigma^2/2), (e^(sigma^2) - 1) e^(2mu + sigma^2) |
| `gamma` | `severity` | shape k > 0, scale theta > 0 | `mean_sd`: k = (m/s)^2, theta = s^2/m | k theta, k theta^2 |
| `generalized_pareto` | `severity` | shape xi in (-1, 2], scale sigma > 0, threshold u >= 0 | `mean_excess`: sigma = (1 - xi) e, for xi < 1 | u + sigma/(1-xi) for xi < 1, else `None`; sigma^2/((1-xi)^2 (1-2xi)) for xi < 1/2, else `None` |
| `spliced` | `severity` | a `lognormal` or `gamma` body truncated to (0, u], a `generalized_pareto` tail above u, the tail probability pi in (0, 1); u at or above the body's median | `tail_probability_of_body`: pi = the body's own probability above u, so below u the splice is the body unchanged | from the body's partial moments and the tail's; `None` where the tail's is |
| `pert` | `expert` | min < max, mode in [min, max], weight w > 0 (4 unless stated); a beta with alpha = 1 + w (mode - min)/(max - min), beta = 1 + w (max - mode)/(max - min) | | (min + w mode + max)/(w + 2), the scaled beta's |
| `triangular` | `expert` | min < max, mode in [min, max] | | (min + mode + max)/3, (a^2 + b^2 + c^2 - ab - ac - bc)/18 |

Every splice's CDF is continuous at u, whatever its tail probability: the body
part reaches 1 - pi there and the tail starts from it. Its density in general is
not continuous; `tail_probability_of_body` keeps the body's own shape below u,
unscaled, and lets the tail replace only the body's mass above it.

**Expert ranges keep their assumptions explicit.** A `pert` or `triangular` takes
the parameter's `source_type` and a `sparse` mark, and is refused
(`expert_not_allowed`) unless the source type is `EXPERT_ESTIMATE` or the data
are marked sparse: an expert's range never stands in for data that exists
(owner's specification, section 7.1). Both are written into the record, and a run
lists the parameters that rest on an expert range (`expert_parameters`), which
should lower the confidence grade (step 7b).

**Infinite moments are `None`, never a float Infinity.** A generalized Pareto's
mean is infinite for xi >= 1 and its variance for xi >= 1/2; a splice whose tail
has either inherits it. Whatever is finite in theory but too large for a binary64
float is refused when the distribution is built (`out_of_range`): a mean, a
variance or a second moment (a lognormal with a very large sigma, a PERT or
triangle whose variance squares a width of 1e200), a width (max - min past the
largest float), a generalized Pareto's scale over its shape, and its largest
draw (its endpoint for xi < 0, otherwise its quantile at numpy's largest standard
exponential, about 44.4: `LARGEST_EXPONENTIAL` is 45); so is a lognormal whose
median e^mu underflows to zero. No accepted distribution has an Infinity or a NaN
in a moment, a quantile below 1 or a draw. A lognormal's variance is computed in
logarithms, so e^(sigma^2) - 1 overflowing alone does not refuse a variance that
holds.

Every distribution gives `sample(rng, n)`, `cdf(x)`, `ppf(p)` (also `quantile`),
`mean` and `variance`. A quantile is the smallest x with `cdf(x) >= p`, for
0 < p < 1: closed form where there is one (lognormal, generalized Pareto,
triangular, and a splice through its parts), otherwise by bisection to the last
bit of a float (gamma, beta, PERT), and the smallest whole number for a count.
The CDFs use no third-party special functions: the regularized incomplete gamma
and beta functions are computed here (series and continued fractions, with
Stirling's correction for large shapes so the prefactor keeps its digits), and the
normal quantile is the standard library's (`statistics.NormalDist`, Wichura's
AS241). During development they were checked against SciPy 1.16.2 and mpmath to
about 1e-12, relative, over the ranges the tests use; neither is a dependency.

`sample` draws only from the `numpy.random.Generator` it is given: never numpy's
or Python's global RNG, and never a `RandomState` (`rng_malformed`). A count's
draws are int64, a cost's float64.

### 23.2 Refusal codes

`distributions.REFUSALS`, raised as `DistributionRefused`:

| Code | Refused |
|---|---|
| `not_a_number` | a parameter that is not an int, a float or a Decimal: a bool, text, None |
| `not_finite` | NaN or Infinity |
| `out_of_range` | a mean, variance, second moment, width, scale over shape, largest draw or count too large to hold as a float or to sample; a lognormal median too small to hold |
| `scale_not_positive` | a scale (sigma, a gamma or Pareto scale) or a rate at or below zero |
| `value_not_positive` | a value a form is built from at or below zero: a lognormal's median or quantile, a mean, a standard deviation, a variance, a mean excess |
| `shape_out_of_range` | a gamma or beta shape or a negative-binomial size at or below zero, a PERT weight at or below zero, a generalized Pareto shape outside (-1, 2] |
| `probability_out_of_range` | a zero inflation outside [0, 1); a negative-binomial p, a splice's tail probability or a quantile's p outside (0, 1) |
| `range_inverted` | min not below max, P10 not below P90, a median not below P90 |
| `mode_out_of_range` | an expert's mode outside [min, max] |
| `not_overdispersed` | a negative binomial whose variance is not above its mean |
| `threshold_out_of_range` | a negative Pareto threshold; a splice threshold at zero or below its body's median |
| `component_unsupported` | a splice whose body is not a lognormal or gamma, or whose tail is not a generalized Pareto |
| `trials_malformed` | trials and successes not whole numbers with 0 <= successes <= trials, trials >= 1 |
| `expert_not_allowed` | a PERT or triangular for a source other than `EXPERT_ESTIMATE` whose data are not marked sparse |
| `source_type_unrecognised` | a source type not one of the eight |
| `sparse_malformed` | a sparse mark that is not True or False |
| `form_unrecognised` | a form the distribution does not list, or `given` not (name, value) pairs |
| `rng_malformed` | a sample from anything but an explicit numpy Generator |
| `sample_size_out_of_range` | a sample size that is not a whole number from 0 to 10,000,000 |

`simulation.REFUSALS`, raised as `SimulationRefused`:

| Code | Refused |
|---|---|
| `seed_malformed` | a seed that is not a whole number from 0 to 2^64 - 1 |
| `draws_out_of_range` | draws that are not a whole number from 1,000 to 1,000,000 |
| `events_over_limit` | a compound run whose events, across all its years, exceed 10,000,000 (checked before any event is sampled) |
| `parameter_name_malformed` | a name that is not 1 to 100 lowercase ASCII letters, digits and `_`, starting with a letter |
| `parameters_malformed` | parameters that are not a non-empty mapping of names to distributions |
| `frequency_not_a_count` | a frequency that is not a count distribution |
| `evaluate_missing` | no function for more than one parameter, or one that cannot be called |
| `outcome_malformed` | a function that does not return one number per draw |
| `outcome_not_finite` | an outcome that is NaN or Infinity |
| `outcome_negative` | an outcome below zero: every outcome is a loss, and no benefit model is enabled |
| `out_of_range` | a year's loss (a compound sum), or a mean or variance of the outcomes, too large to hold as a float |
| `values_over_budget` | a run that would hold more than 30,000,000 values at once (section 23.9), refused before anything is sampled, and in a compound run once the years' counts are drawn and before any event is |
| `percentile_out_of_range` | a severe-but-plausible percentile that is not an int or Decimal from 90 to below 100 |
| `model_version_blank` | a run that does not name its model version |
| `scenario_id_malformed` | a scenario id that is blank or not text |

A reporting currency is checked as money checks it (section 11.4), with money's
codes. A broken runtime invariant (section 23.5) is `InvariantBroken`: a defect in
the engine or in the function it evaluated, never the input's fault.

### 23.3 Randomness: one seed, named sub-streams

A run has one seed, a whole number from 0 to 2^64 - 1. Each parameter draws from
its own stream, `Generator(PCG64(SeedSequence(entropy=seed, spawn_key=K)))`,
where K is the SHA-256 of `mythos.economics.substream/v1`, a zero byte and the
parameter name's UTF-8, read as eight little-endian 32-bit words. A parameter's
draws depend on the seed and its own name only: adding, removing or reordering
another parameter never changes them. The frequency draws from the stream named
`@frequency`, which no parameter name can spell. A run issues each stream once (a
second request is a defect: two parameters would draw the same numbers), reads no
global RNG, and depends on nothing that varies with `PYTHONHASHSEED`. The first
draws of one sub-stream are pinned by a test, so a change to the derivation, or to
numpy's PCG64 or SeedSequence, fails until `SAMPLER_VERSION` moves with the pin.

### 23.4 A run

`simulation.run(parameters, evaluate, seed=, model_version=, reporting_currency=,
frequency=None, draws=100_000, severe_percentile=95, scenario_id=None)`.
`evaluate` maps a dict of draw vectors (read-only, one per parameter) to one
outcome per draw, vectorised and pure; step 7b passes the scenario engine's
formulas. A run of one parameter may omit it.

- **Without a frequency** (basis `per_draw`) a draw is one evaluation, and the
  summary is of the outcome. There is no expected annual loss: the engine does not
  know the outcome is annual, and says so (`null`) rather than guessing.
- **With a frequency** (basis `annual_loss`) a draw is a simulated year. N events
  are drawn from the frequency for each year; every event's parameters are drawn
  afresh and evaluated; and the year's loss is the sum of its N event losses,
  accumulated in event order (`compound_annual`), zero for a year with none. The
  percentiles, mean and severe-but-plausible are of the annual loss, the expected
  annual loss is its mean, and the event-loss distribution is summarised beside it
  (when the run has at least 1,000 events).

**Reproducibility is enforced at run time.** The run is sampled twice, each time
from fresh sub-streams, and the two outcome vectors must be identical bit for bit;
a function that reads a global RNG or otherwise is not pure is caught here.

### 23.5 Summary, percentiles and bands

Severe-but-plausible is P95 of annual loss (of the outcome, in a `per_draw` run)
unless the run states another percentile, from 90 to below 100; the percentile is
written into the result.

- **Quantiles** are Hyndman and Fan's type 7, numpy's `'linear'`: sort the n
  outcomes; h = (n - 1) p, computed exactly from the percentile as a fraction;
  q = x[floor(h)] + (h - floor(h)) (x[floor(h) + 1] - x[floor(h)]), in binary64,
  clamped to that interval.
- **The mean** is `math.fsum` of the outcomes (a correctly rounded sum) over n;
  the sample variance is `fsum` of the squared deviations over n - 1; the standard
  error of the mean is the square root of variance over n.
- **Bands**, at 95%: a percentile's is the pair of order statistics at ranks
  floor(np - z s) and ceil(np + z s), s = sqrt(n p (1 - p)), clamped to [1, n]
  (distribution-free); the mean's is the mean minus and plus z standard errors;
  z is the standard normal's 97.5th percentile. They make "within tolerance"
  measurable.
- **Invariants**, checked on every summary: p10 <= p50 <= p90 <= severe, all at
  least zero, a mean at least zero, and each figure inside its band.
- **A mean that does not exist is not estimated.** When any parameter's mean is
  infinite, the mean, the expected annual loss, their standard error and band are
  `null`, and `mean_undefined` names the parameters; the percentiles are given.
- **Nor is an uncertainty that does not exist.** When any parameter's variance is
  infinite (a generalized Pareto with xi >= 1/2, the usual cyber tail, or a splice
  with such a tail), the mean is given, but `standard_error_of_mean` and the
  mean's band are `null`, and `standard_error_undefined` names the parameters: a
  band from the sample's standard error would not cover at its stated level. The
  review measured it at 10,000 draws over 300 seeds: a "95%" band covered the
  true mean in 58% of runs at xi = 0.8 and 17% at 0.95, against 94% at 0.3. The
  percentile bands are distribution-free and stay.

### 23.6 Precision

Floats inside, Decimal outside. Draws and arithmetic are binary64. Each summary
float becomes the Decimal of its repr: the shortest decimal string that reads
back as exactly that float (Python's repr, the same on every IEEE-754 platform),
converted with no rounding, and written in money's one spelling (plain notation,
no exponent, no trailing zeros; section 12.6). It is rounded to the reporting
currency's minor unit only to be shown (`Money.display`, ROUND_HALF_EVEN; section
11.3): 568764.7227033532 is shown as 568764.72 USD. A record holds no float.

### 23.7 The result and its digest

The record carries the owner's specification's result fields (section 15:
`scenario_id`, `model_version`, `seed`, `simulations`, `p10`, `p50`, `p90`,
`mean`, `expected_annual_loss`, `severe_plausible`, `reporting_currency`), and
beside them the basis, the severe percentile, the standard error, the bands,
`mean_undefined` and `standard_error_undefined`, the events, every parameter's and the frequency's record (id, version, parameters,
form, values given), the expert parameters, the sampler's version and methods,
and `outcomes_sha256`: the SHA-256 of every outcome as little-endian binary64,
so the digest covers every draw. `scenario_id` is a placeholder until step 7b.
The schema is `mythos.economics.simulation/v1`. The seed is written as text, so a
reader that holds numbers as doubles cannot round it.

The digest is `sha256:` and the SHA-256 of the record's canonical JSON (sorted
keys, no whitespace, ASCII, no float). It changes with the seed, the draws, any
parameter, the frequency, the model version, the scenario id, the reporting
currency and the severe percentile. The library versions are kept outside it, as
provenance (`numpy`): the digest already covers every draw. Abridged, from 100,000
simulated years of three parameters at seed 2026:

```json
{"schema": "mythos.economics.simulation/v1", "scenario_id": null, "model_version": "example-1",
 "seed": "2026", "simulations": 100000, "reporting_currency": "USD", "basis": "annual_loss",
 "p10": "31200.21030638023", "p50": "568764.722703353", "p90": "3648776.8370299395",
 "mean": "1644950.0589876557", "expected_annual_loss": "1644950.0589876557",
 "severe_plausible": "6053720.56694113", "severe_percentile": "95",
 "standard_error_of_mean": "16636.019599060797", "confidence_level": "0.95",
 "bands": {"p50": ["561945.9126726118", "576212.1189518626"], "...": "..."},
 "mean_undefined": null, "standard_error_undefined": null,
 "events": {"total": 299232, "summary": {"...": "..."}},
 "parameters": {"records": {"id": "lognormal", "version": 1, "kind": "severity",
   "params": {"mu": "7.600902459542082", "sigma": "1.7967166947477073"},
   "form": "median_p90", "given": {"median": "2000", "p90": "20000"},
   "mean": "10046.683913013187", "variance": "2446075982.1362343"}, "...": "..."},
 "frequency": {"id": "poisson", "version": 1, "params": {"rate": "3"}, "...": "..."},
 "expert_parameters": [], "sampler": {"version": 1, "bit_generator": "PCG64", "...": "..."},
 "outcomes_sha256": "sha256:c40769c3...80b09",
 "digest": "sha256:bcf87767...db060",
 "display": {"p50": "568764.72 USD", "...": "..."}, "provenance": {"numpy": "2.3.3"}}
```

### 23.8 Reproducibility across machines

The same seed, inputs, model version and numpy give the same digest. The tests
show it for two interpreters with different `PYTHONHASHSEED`, and for numpy's
SIMD dispatch: numpy picks an AVX-512, AVX2 or baseline implementation of its own
`exp` and `log` by CPU, and they differ in the last bit, so the samplers use none
of them. A lognormal's and a generalized Pareto's draws go through `exp_portable`
and `expm1_portable`, built from IEEE-754 basic operations alone (Cody and Waite's
reduction, Taylor's series, an exact power-of-two scale), within one and two units
in the last place, and Infinity, zero (or -1) and NaN beyond the range of a float,
as any exp gives them; every other draw is numpy's own C sampler. A compound
year's loss is `np.add.reduceat` over its events, the same additions in the same
order on every CPU. During development
the digests were also the same with glibc's FMA variants turned off
(`GLIBC_TUNABLES`), which change libm's `exp`. What remains platform-dependent is
the C library's `log`, `log1p` and `pow` that numpy's samplers call in rare
branches (a ziggurat's tail, a rejection test, a gamma shape below 1): a libm
that differs there in the last bit can change a draw, and the digest with it,
while the summary agrees to the last few digits. That is the tolerance of the
owner's specification, section 35; a replay on another platform compares the
summary, not only the digest.

### 23.9 Limits and timing

100,000 draws by default, from 1,000 to 1,000,000; at most 10,000,000 events
across a compound run's years; at most 10,000,000 draws from one `sample` call.

**Memory is bounded by the limits.** Step 7b runs this inside a Django process,
so a run that fits the limits cannot exhaust memory. A run holds at most
30,000,000 values at once (`MAX_VALUES`, 240 MB as binary64), counted by
`values_held` before anything is sampled (in a compound run, once the years'
event counts are drawn and before any event is): (parameters + 3) vectors of the
sampled length (the draws, or the events of a compound run) and, in a compound
run, 8 per simulated year. The 3 are the first sample's outcomes, kept while the
run samples again (section 23.4), the evaluated function's result, and one for its
temporaries or a splice's buffer; the 8 are both samples' counts and annual
losses and the compound sum's indices. More is refused (`values_over_budget`).
So 27 parameters fit a million draws, and 28 do not; three parameters fit a
million years of 3.5 events each, and eight parameters at 9.9 events a year (about
855 MiB before this rule) do not.

The engine keeps its own transients inside that count. Every sampler writes in
place; the portable exp, the triangular inversion and the sums work in blocks of
16,384 values; a year's sum uses one index per year, never one per event; and a
splice draws its body in chunks of at most 1,000,000 values and at most a quarter
of its sample (`SPLICE_CHUNK`), so one sample of n holds about 2.5 n values at
its peak, never several times n (before, one round drew about 4 n at once, past
`MAX_SAMPLE`). The traced peak of a run is at most 8 bytes for each value counted,
plus about 1 MB of block buffers (`FIXED_BUFFER_BYTES`), plus whatever the
evaluated function allocates beyond one vector. Measured with `tracemalloc` on
the build machine: 236 MB for 27 parameters of a million draws (the budget is
240 MB); 168 MB for three parameters over a million years of 3.5 events; 180 MB
for one splice over a million years of 5.4 events; between 0.7 and 1.0 of the
count for smaller runs.

**Timing,** measured on the build machine (4 cores, numpy 2.3.3), each run
sampled twice as section 23.4 says: 100,000 draws of one lognormal in 0.025 s;
100,000 simulated years of a three-parameter formula with a Poisson(3) frequency
(about 300,000 events) in 0.13 s; 1,000,000 such years in 1.5 s. The test of a
default run allows 60 s, so it catches a per-draw Python loop and never CI load.

### 23.10 Safety

Neither module is on any stop path, and nothing Django loads at start imports
either, or numpy: `test_django_and_the_urlconf_never_import_the_probabilistic_engine`
runs `django.setup()` and loads every URLconf in a fresh interpreter and finds
neither module nor numpy loaded.
`test_a_broken_probabilistic_engine_never_takes_down_the_scan_stop` runs a fresh
pytest under a plugin that makes numpy and both modules unimportable before Django
loads, as an import-time fault would: the scan's Stop still resolves, answers 202
and is saved. `test_nothing_but_the_models_registration_imports_economics`
(section 2) still holds: nothing outside the package imports it but the models'
registration.

### 23.11 What is not wired yet (step 7b)

Step 7b (section 25) wires the sampler to the scenario engine: each formula has a
vectorised twin and a run evaluates the scenario's components, events and insurance;
a `FinancialParameter` may state a distribution, and a rule gives one to every other
parameter or refuses it; a `SimulationResult` records each run, idempotently; the
`scenario_id` is the scenario version's uuid; and the uncertainty shared by a year's
events is separated from the variation between them (section 25.2). What remains:

- **Served by step 6** (section 27). Step 8 builds and signs the receipt
  (section 26).
- **Step 8 computes the confidence grade**, the sensitivity analysis and the
  Validity Card (section 26); a material expert figure lowers the grade there.
- **No dependency between parameters** beyond that sharing: no copula, no
  shared-cause event, no correlation between events, and the frequency's parameters
  are fixed for the run.
- **One currency.** A run is in its reporting currency; nothing converts inside
  it, and currency uncertainty stays separate (section 3, rule 6).

### 23.12 Decisions this step takes, which the owner may change

1. Severe-but-plausible is P95 of annual loss unless a run states another
   percentile, from 90 to below 100.
2. The confidence bands are at 95%.
3. A generalized Pareto shape is accepted in (-1, 2]: below -1 the density rises
   toward its endpoint, which is no tail, and above 2 the tail is heavier than
   any loss data this engine is calibrated for.
4. A splice's threshold is at or above its body's median.
5. The Beta-Binomial update's default prior is the uniform Beta(1, 1); a stated
   prior is recorded with the evidence.
6. PERT's weight on the mode is 4 unless stated.
7. A run takes 1,000 to 1,000,000 draws, and at most 10,000,000 events.
8. A run whose inputs include an infinite mean reports no mean and no expected
   annual loss, rather than a sample mean that estimates nothing, even where the
   function it evaluates might cap the loss.
9. numpy is pinned in CI's set as well as the service's, at the same version
   (`numpy==2.3.3`).
10. A run whose inputs include an infinite variance (but a finite mean) reports
    the mean without a standard error or a mean band.
11. A run holds at most 30,000,000 values at once (240 MB as binary64); a
    process that can spare more may raise `MAX_VALUES`, one constant.
12. Every splice's CDF is continuous at u; the form that keeps the body unchanged
    below u is `tail_probability_of_body` (named `continuous_at_threshold` before
    any record carried it).

## 24. The scenario builder (MVP step 5)

The scenario builder turns SPINE effects, and the findings that enable them, into
causal loss events, through six templates of the banking pack (the owner's
specification, sections 6 and 22). **Findings that enable the same effect join ONE
loss event**: the engine never attaches a figure to a finding, and five findings that
enable one payment loss make ONE event whose loss is not multiplied (the
specification's own test, section 27). The pure half is
`assurance/economics/engine/templates.py` (the templates, the attributes and the
vocabularies; no Django); the Django half is `assurance/economics/builder.py`
(resolving, grouping, writing and reading) and `assurance/economics/scenario_api.py`
(the two routes). Migration `0063_causal_graph_and_scenario_builds.py`. Tests:
`tests/test_economics_templates.py` (no database) and
`tests/test_economics_builder.py`.

### 24.1 The causal graph

The graph is the smallest set of records that makes the invariant enforceable. It
reuses what exists -- SPINE's findings (`Finding`), assets (`Asset`) and signed
observed effects (`WorkflowChainOutcome` rows carrying a `mythos.observed-effect`
document), #141's `FinancialScenario`, and #146's `CustomerParameterSet`,
`FinancialParameter`, `LossEvent` and `LossComponent` -- and adds three records, all
append-only, tenant-scoped through their scenario, and versioned with it (a rebuilt
scenario is a new version that supersedes the old, section 6):

| Record | Holds |
|---|---|
| `CausalEffect` | one effect of one scenario version: its key, origin (`observed` or `hypothetical`), type, the asset it is bound to (a node, by uuid) and the business process; for an observed effect, the SPINE row's uuid (`observed_effect`), the digest its signature covers (`observation`), the effect as the receipt names it (`spine_effect`: workflow and tool) and when it was observed; the template it is assigned to and every template that covers it; and the ONE `LossEvent` it is in (a hypothetical effect's row is in the one event of its key that prices it, and it takes part in every event of its key: section 24.5) |
| `EffectFinding` | one finding enabling one effect, as a `prerequisite`, an `amplifier` or an `alternate_path` (Finding ENABLES Effect) |
| `ScenarioBuild` | how one scenario version was built: the parameter-set version it read, the currency and as-of date, the builder, grouping and pack versions, the canonical inputs, and their content digest, unique per deployment |

The linkage is finding to effect (`EffectFinding`), effect to loss event
(`CausalEffect.loss_event`), and loss event to its components, which cite the
parameters they read (#146). An effect's attributes are the scenario's financial
parameters, named `<effect key>.<attribute>`, each with its `source_type` and
evidence. A finding, an asset and an observed effect are named by uuid, never copied
(section 8), and resolved in the scenario's own deployment when the scenario is built.
An attribute that more than one effect of one event states is read at the larger loss
across them (section 24.5): a parameter of the scenario too, named
`<event key>:<attribute>`, whose `derived_from` cites every effect attribute it was
taken across.

None of the three has an account column; each goes with its deployment through its
scenario's cascade; their foreign keys have no reverse accessor (`related_name="+"`);
the base manager is Django's plain one. Their permitted writer is the builder, and
only it (section 6).

### 24.2 Effects

An effect is a SPINE observed effect or a declared hypothetical effect:

- `observed`: the build names the SPINE observed effect by its row's uuid. It must
  stand: its signature verifies NOW against the configured keyring, the key is an
  observed-effect key (`observed_effect` evidence), it is `held`, and its evidence is
  exactly the document its signature names, for this deployment
  (`observed_effect_not_in_force` otherwise). Its time is the row's, never the
  caller's. An attribute of it rests on `MYTHOS_OBSERVED` only where the attribute
  is observable -- a rate, a count or a duration an assessment sees when the effect
  happens (the table's last column; `observed_source_not_observable` otherwise: a
  money amount or a market figure is `CUSTOMER_PROVIDED`, `EXPERT_ESTIMATE` or
  another source that is not an observation) -- and only where its `evidence_ref`
  is the observed effect it came from, its SPINE effect digest, alone or followed by
  a space and a note (`observed_source_unbound` otherwise: a digest that is only
  mentioned in the text, or that follows other words, binds nothing, and one
  `evidence_ref` naming two digests binds only the first). The signed document carries no figure:
  what it proves is which effect was seen, and the figure must say it is that
  effect's.
- `hypothetical`: declared by an analyst, it rests on at least one finding that
  enables it (`effect_without_finding`), and none of its attributes is
  `MYTHOS_OBSERVED`: nothing was observed (`observed_source_on_hypothetical`).

Each effect has a type and a business process from the pack's vocabularies, and
states the attributes the templates read, each in the parameter-set document's form
(unit, low, base, high, currency for money, `source_type`, `evidence_ref`,
`effective_date`, optionally `fresh_until`, and from step 6 optionally the
`distribution` it draws from in a simulation, held to its figures as a parameter set's
is: section 19.4), so every rule of a parameter (section 14) holds for it. A stated
distribution is part of the build's inputs, so the same effects stating another are
another build; one stating none keeps the build digest it had before.

Effect types:

| Code | Meaning |
|---|---|
| `funds_transfer_altered` | an agent initiated a payment, wire or ACH transfer, or changed one (its destination, its amount), outside its authority |
| `approval_bypassed` | an agent's action took effect without the approval it needed |
| `cross_customer_disclosure` | one customer's data reached another customer |
| `customer_misstatement` | a customer-service AI told customers something false about a fee, a rate, a product or a policy |
| `fraud_aml_control_failure` | a fraud or AML workflow missed, closed or failed to escalate cases it should have caught |
| `provider_outage` | a third-party model or provider a critical operation depends on was unavailable |

Business processes: `payments`, `lending`, `account_servicing`, `customer_service`,
`fraud_aml`, `operations`. Origins: `observed`, `hypothetical`. Finding roles:
`prerequisite`, `amplifier`, `alternate_path`.

The attributes (`templates.ATTRIBUTES`):

| Attribute | Unit | Meaning | Observable |
|---|---|---|---|
| `success_rate` | `ratio` | the share of attempts that produced the effect, as tested | yes |
| `exploitable_window_hours` | `hours` | how long the condition stays exploitable before detection | yes |
| `incident_response_cost` | `money` | incident response, as a range its evidence gives | no |
| `legal_response_cost` | `money` | legal and regulatory response, as one range its evidence gives | no |
| `affected_customers` | `count` | customers the effect reaches | yes |
| `contact_rate` | `ratio` | the share of affected customers who contact support | no |
| `handling_hours` | `hours` | average handling time per contact | no |
| `forensics_fixed_cost` | `money` | the fixed part of forensics or investigation | no |
| `investigation_hours` | `hours` | hours of forensics or investigation | no |
| `counsel_hours` | `hours` | hours of external counsel | no |
| `regulatory_response_cost` | `money` | regulatory response, as scenario bounds its evidence grounds (never a predicted penalty) | no |
| `churn_rate` | `ratio` | the extra share of affected customers who leave, from the customer's own data | no |
| `margin_per_customer_per_year` | `money_per_unit` | recurring margin per customer per year | no |
| `churn_recovery_years` | `years` | years until lost margin is won back | no |
| `market_capitalisation` | `money` | the company's market capitalisation (public-company analysis) | no |
| `share_price_decline` | `ratio` | the share-price decline attributed to the effect | no |
| `restitution_per_customer` | `money_per_unit` | the amount owed to each affected customer | no |
| `missed_cases` | `count` | fraud or AML cases the workflow missed | yes |
| `loss_per_missed_case` | `money_per_unit` | the fraud loss per missed case | no |
| `rework_cost` | `money` | reworking and reprocessing the cases, as a range | no |
| `repeat_count` | `count` | how many times the unauthorized effect repeats | yes |
| `loss_per_event` | `money_per_unit` | the amount one unauthorized effect moves or loses | no |
| `recovery_fixed_cost` | `money` | the fixed part of restoring the control or the service | no |
| `recovery_hours` | `hours` | engineering hours to restore the control or the service | no |
| `outage_hours` | `hours` | how long the provider is unavailable | yes |
| `sla_credit_per_hour` | `money_per_hour` | SLA credits owed to customers per hour of outage | no |
| `sla_credit_cap` | `money` | the contracts' cap on those credits | no |

### 24.3 The six templates

`mythos.economics.banking-pack/v1` (`templates.PACK`). Six of the specification's
eight banking families: payment, wire and ACH agent misuse; cross-customer data
exposure; customer-service AI misstatement; fraud/AML workflow failure; agent
approval bypass; third-party model or provider outage. Loan or underwriting agent
error and model drift are not modelled in this version.

A template is a versioned, named mapping from an effect's type, process and
attributes to its loss event's components: for each, the family, the formula of the
catalogue (section 15) and, for every input of the formula, its ONE source, either a
variable of the customer parameter set (`parameter_set`) or an attribute of the
effect (`effect_attribute`). **A template never invents a number**: a source is a kind
and a name, and nothing else (`test_a_template_holds_no_figure`). Every value a
component reads is a parameter recorded with its `source_type` and evidence; an input
whose source holds nothing is left unbound, and the formula makes the component
`unknown`, never zero (section 15): with no parameter set and no attribute, every
component of every template is unknown and names every input it lacks
(`test_a_source_that_holds_nothing_leaves_the_component_unknown_never_zero`). A
template binds no insurance term; insurance is applied once, from the parameter set's
policy, when an event is assessed (section 17). In the tables, `+` is an input that
increases the loss and `-` one that decreases it.

#### `payment_agent_misuse`, version 1, precedence 1: Payment / wire / ACH agent misuse

Covers `funds_transfer_altered` on any process; `approval_bypassed` on `payments`.

| Component | Family | Formula | Inputs: direction, source |
|---|---|---|---|
| `direct-loss` | `direct_financial` | `repeat_in_window` v1 | `transactions_per_day` (+) from the set: `transactions_per_day`; `window_hours` (+) from the effect: `exploitable_window_hours`; `success_rate` (+) from the effect: `success_rate`; `value_per_transaction` (+) from the set: `average_transaction_value`; `recovery_rate` (-) from the set: `recovery_rate` |
| `incident-response` | `incident_response` | `lump_sum` v1 | `amount` (+) from the effect: `incident_response_cost` |
| `legal-regulatory-response` | `legal` | `lump_sum` v1 | `amount` (+) from the effect: `legal_response_cost` |

Direction notes:

- recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest
- the exploitable window is the largest uncertainty (specification, section 30); a longer window never lowers the loss
- the success rate is the tested proportion (7 of 20 in section 30), a point; its interval is the probabilistic engine's
- transactions per day and the average transfer are the customer's own figures, never the test's amounts
- a lump-sum range is read as its evidence gives it, low, base and high; where the evidence gives a range and no base, the declaration's base is its midpoint (spec, section 22, decision 5)
- remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, decision 2)

#### `cross_customer_data_exposure`, version 1, precedence 2: Cross-customer data exposure

Covers `cross_customer_disclosure` on any process.

| Component | Family | Formula | Inputs: direction, source |
|---|---|---|---|
| `notification` | `notification` | `per_affected_plus_fixed` v1 | `affected` (+) from the effect: `affected_customers`; `unit_cost` (+) from the set: `notification_unit_cost`; `fixed_cost` (+) from the set: `notification_fixed_cost` |
| `support` | `notification` | `support_contacts` v1 | `affected` (+) from the effect: `affected_customers`; `contact_rate` (+) from the effect: `contact_rate`; `handling_hours` (+) from the effect: `handling_hours`; `loaded_rate` (+) from the set: `support_agent_hourly_rate` |
| `forensics` | `incident_response` | `fixed_plus_hours` v1 | `fixed_cost` (+) from the effect: `forensics_fixed_cost`; `hourly_rate` (+) from the set: `security_responder_hourly_rate`; `hours` (+) from the effect: `investigation_hours` |
| `legal` | `legal` | `fixed_plus_hours` v1 | `fixed_cost` (+) from the set: `legal_retainer`; `hourly_rate` (+) from the set: `external_counsel_hourly_rate`; `hours` (+) from the effect: `counsel_hours` |
| `regulatory` | `regulatory_compliance` | `lump_sum` v1 | `amount` (+) from the effect: `regulatory_response_cost` |
| `customer-loss` | `customer_loss` | `churned_margin` v1 | `customers` (+) from the effect: `affected_customers`; `churn_rate` (+) from the effect: `churn_rate`; `margin_per_customer_per_year` (+) from the effect: `margin_per_customer_per_year`; `recovery_years` (+) from the effect: `churn_recovery_years` |
| `share-price-reaction` | `market_value` | `share_price_reaction` v1 | `market_capitalisation` (+) from the effect: `market_capitalisation`; `price_decline` (+) from the effect: `share_price_decline` |

Direction notes:

- the affected population drives notification, support and customer loss alike: one parameter, read by each in the same direction
- customer loss is computed only from the customer's own churn figure (CUSTOMER_PROVIDED); any other source makes it unknown (specification, section 31)
- regulatory response is scenario bounds its evidence grounds, never a predicted penalty
- the share-price reaction is market value: reported on its own line and never added to cash loss; unknown unless the effect states the market capitalisation and the decline
- remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, decision 2)

#### `customer_service_ai_misstatement`, version 1, precedence 3: Customer-service AI misstatement

Covers `customer_misstatement` on any process.

| Component | Family | Formula | Inputs: direction, source |
|---|---|---|---|
| `restitution` | `customer_restitution` | `per_affected` v1 | `affected` (+) from the effect: `affected_customers`; `amount_per_affected` (+) from the effect: `restitution_per_customer` |
| `complaint-handling` | `notification` | `support_contacts` v1 | `affected` (+) from the effect: `affected_customers`; `contact_rate` (+) from the effect: `contact_rate`; `handling_hours` (+) from the effect: `handling_hours`; `loaded_rate` (+) from the set: `support_agent_hourly_rate` |
| `legal` | `legal` | `fixed_plus_hours` v1 | `fixed_cost` (+) from the set: `legal_retainer`; `hourly_rate` (+) from the set: `external_counsel_hourly_rate`; `hours` (+) from the effect: `counsel_hours` |
| `compliance-review` | `regulatory_compliance` | `lump_sum` v1 | `amount` (+) from the effect: `regulatory_response_cost` |

Direction notes:

- the customers told the misstatement drive restitution and complaint handling alike
- complaint handling is the call-center work the misstatement causes (the notification family, which holds call-center cost)
- remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, decision 2)

#### `fraud_aml_workflow_failure`, version 1, precedence 4: Fraud/AML workflow failure

Covers `fraud_aml_control_failure` on any process; `approval_bypassed` on `fraud_aml`.

| Component | Family | Formula | Inputs: direction, source |
|---|---|---|---|
| `missed-fraud` | `direct_financial` | `repeat_loss` v1 | `repeat_count` (+) from the effect: `missed_cases`; `loss_per_event` (+) from the effect: `loss_per_missed_case`; `recovery_rate` (-) from the set: `recovery_rate` |
| `case-rework` | `recovery` | `lump_sum` v1 | `amount` (+) from the effect: `rework_cost` |
| `investigation` | `incident_response` | `fixed_plus_hours` v1 | `fixed_cost` (+) from the effect: `forensics_fixed_cost`; `hourly_rate` (+) from the set: `security_responder_hourly_rate`; `hours` (+) from the effect: `investigation_hours` |
| `regulatory-response` | `regulatory_compliance` | `lump_sum` v1 | `amount` (+) from the effect: `regulatory_response_cost` |

Direction notes:

- recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest
- missed cases are the cases the workflow should have caught, not every case it saw
- regulatory response is scenario bounds its evidence grounds, never a predicted penalty
- remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, decision 2)

#### `agent_approval_bypass`, version 1, precedence 5: Agent approval bypass

Covers `approval_bypassed` on any process.

| Component | Family | Formula | Inputs: direction, source |
|---|---|---|---|
| `unauthorized-effect` | `direct_financial` | `repeat_loss` v1 | `repeat_count` (+) from the effect: `repeat_count`; `loss_per_event` (+) from the effect: `loss_per_event`; `recovery_rate` (-) from the set: `recovery_rate` |
| `control-recovery` | `recovery` | `fixed_plus_hours` v1 | `fixed_cost` (+) from the effect: `recovery_fixed_cost`; `hourly_rate` (+) from the set: `engineering_hourly_rate`; `hours` (+) from the effect: `recovery_hours` |
| `incident-response` | `incident_response` | `lump_sum` v1 | `amount` (+) from the effect: `incident_response_cost` |

Direction notes:

- recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest
- the size of one unauthorized effect is the effect's own, stated with its source (an amount is never MYTHOS_OBSERVED: the signed observation carries none); the repeat count is how often it recurs before the approval control is restored
- remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, decision 2)

#### `third_party_provider_outage`, version 1, precedence 6: Third-party model/provider outage

Covers `provider_outage` on any process.

| Component | Family | Formula | Inputs: direction, source |
|---|---|---|---|
| `interruption` | `business_interruption` | `interruption` v1 | `interruption_hours` (+) from the effect: `outage_hours`; `value_per_hour` (+) from the set: `margin_per_hour` |
| `failover-recovery` | `recovery` | `fixed_plus_hours` v1 | `fixed_cost` (+) from the effect: `recovery_fixed_cost`; `hourly_rate` (+) from the set: `engineering_hourly_rate`; `hours` (+) from the effect: `recovery_hours` |
| `sla-credits` | `contractual` | `capped_credit` v1 | `credit_per_hour` (+) from the effect: `sla_credit_per_hour`; `breach_hours` (+) from the effect: `outage_hours`; `contract_cap` (+) from the effect: `sla_credit_cap` |

Direction notes:

- the outage's length drives the interruption and the SLA credits alike: one parameter, read by both in the same direction
- the interruption is read at the critical service's MARGIN per hour, not its revenue: revenue lost is not all loss
- the customer's recovery time objective is a target, never read as the outage's length
- SLA credits are capped by the contracts' cap; a higher cap never lowers the loss

Each template has a worked example in `tests/test_economics_templates.py`, every
figure computed by hand in the comments and labelled SYNTHETIC / ILLUSTRATIVE.
Section 30's bank payment agent through `payment_agent_misuse` gives exactly #146's
known answer (direct loss USD 164,062.50 / 1,435,546.875 / 3,937,500; gross cash loss
USD 394,062.50 / 2,425,546.875 / 5,687,500), and so does section 31's cross-customer
exposure through `cross_customer_data_exposure` (at least USD 239,000 / 746,250 /
2,580,000 gross, and at least USD 100,000 / 231,250 / 1,580,000 retained under the
set's policy). `tests/test_economics_builder.py` builds both again from effects,
section 30 from a SPINE observed effect, and reads back the same figures.

### 24.4 Scope and precedence

A template covers the effect types it names, on any business process or only on
those it names. Where two cover one effect, the one of lower precedence takes it, and
ONLY it (`templates.select`): the precedence is a total order, 1 to 6 in the order
above. Two overlaps exist in this version, both of an `approval_bypassed` effect: on
`payments` it is a payment loss (`payment_agent_misuse`, precedence 1, not
`agent_approval_bypass`, 5), and on `fraud_aml` a fraud/AML workflow failure
(`fraud_aml_workflow_failure`, 4). Every effect type is covered on every process.
The effect records every template that covers it (`in_scope_of`) beside the one it was
assigned to.

### 24.5 The grouping key, and one effect, one event

`mythos.economics.grouping/v2` (`builder.GROUPING_VERSION`; `v1` until the owner's
decision of 12 Oct 2026, section 24.9). The members of a build
are its finding links and the effects no finding enables (an observed effect rests on
its observation). Each member's key is the template its effect is assigned to (id and
version), its asset and its business process. The effect type is NOT in the key: the
template encodes it, and two effect types one template takes on one asset and process
are one loss -- a transfer altered and an approval bypassed on one payments agent are
both the payment loss, and pricing the customer's transaction pool once per type
would double it; the grouping key never names a finding, so every finding that
enables one effect has that effect's key and a finding never makes an event of its
own. Within one key:

- **every observation of one SPINE effect joins ONE event**, however far apart they
  are: the observed effects are first gathered by the effect as the receipt names it
  (`spine_effect`: workflow and tool), each such effect one unit, so one effect
  observed twice, a day apart, is one effect and one loss, not two. One SPINE effect
  declared within one build with another asset, process or effect type would be two
  events: it is refused (`spine_effect_inconsistent`);
- a unit with an observation within 24 hours (`builder.GROUPING_WINDOW`) of an
  observation of ANY member of an event joins that event: a key's events are the
  connected components of "within 24 hours" over all its observations, each unit
  held together whatever the window. A chain of effects, each within 24 hours of the
  next, is one event however long it runs; one more than 24 hours from every member
  is another. So adding an effect can MERGE events, and never splits one or moves an
  effect from one to another. The window joins DISTINCT effects of one key; it never
  splits one;
- an effect with no time (a hypothetical one) cannot be placed in a window and is
  never counted as an occurrence of its own: it takes part in EVERY event of its key,
  so which event is first never decides what it adds; where the key has no observed
  effect, the hypothetical effects make one event together. It adds no event, and
  its loss is counted ONCE (`builder.price`): a key's hypothetical effects are PRICED
  in the one event where they add the most gross cash loss at BASE -- the event's
  loss with them less its loss without them -- ties going to the larger gain at
  high, then at low, then to the earliest event. That event records them (their
  `CausalEffect` rows and their findings') and reads their figures in its larger
  loss, citing them (in `derived_from`, or the attribute itself where one alone
  states it). Every other event of the key lists them, with their findings, marked
  `joined` (section 24.8), and reads NONE of their figures: its components are its
  own effects'. One pricing event serves all three points, since an event read with
  them at one point and without them at another could state a low above its base,
  which no parameter or component may (`range_inverted`).

Grouping `v1` measured the window from an event's FIRST observation and joined a
hypothetical effect to the key's first event only; adding an effect could then split
an event or move a hypothetical one, and lower the scenario's gross (section 24.9). A
build recorded under `v1` reads as it was built: the events route lists a
hypothetical effect in every event of its key for a build of any grouping but `v1`.

An event's key is `ev-` and 24 hex digits of the SHA-256 of the grouping version, the
key and its earliest observation (`undated` for an event of hypothetical effects), so
a finding added later leaves it unchanged. The event names, as its SPINE effect, the
one of its earliest observation, and as its trigger the types of every effect taking
part in it, sorted and joined by `+`.

**No effect leads.** For each attribute its template reads, an event reads the value
that gives the LARGER loss across ALL its effects, observed and hypothetical alike,
for each point separately -- low, base and high -- by the direction of the formula
inputs that read it: the highest where the input increases the loss, the lowest where
it decreases it (`templates.larger_loss`, `mythos.economics.larger-loss/v1`). Joined
effects never understate, and adding an effect to an event never lowers that event's
loss (`test_adding_an_effect_never_lowers_the_events_loss`). Under grouping v2 adding
an effect to a BUILD never splits an event or moves an effect, and never lowers the
scenario's gross at base unless it merges events, which count their shared pool once;
at high or low it can, where the added effect moves the pricing of the key's
hypothetical effects to another event (section 24.9;
`test_adding_an_effect_never_splits_an_event_and_prices_a_hypothetical_once`). The value does not depend on
how the effects' keys are spelled (`test_joined_effects_read_the_larger_loss_whatever_their_keys`);
an exact tie is one value, and the effect cited for it is the lowest key. One effect
stating the attribute is read as itself. Two or more make a parameter of the scenario,
`<event key>:<attribute>`, `CALCULATED`, whose `derived_from` cites every effect
attribute it was taken across; the events route lists them. Its dates are those of the
effects that SUPPLY a point of it, never of an effect whose figure is nowhere in the
value: it holds from the latest date any of those holds from and is fresh no longer
than the stalest of them (`test_a_merged_value_is_fresh_no_longer_than_the_stalest_figure_that_supplies_it`);
where that latest date is after the stalest `fresh_until`, no parameter can be fresh
before it holds, so the value is fresh until the day it holds from. Where the inputs accept
only some sources -- the churn rate only the customer's own (section 31) -- an effect
whose source they refuse takes no part while one they accept does, and two of the
customer's own figures make a value that keeps that source type, since each point is
one of those figures unchanged; where none is accepted, all take part and the
component is unknown, as it is for any one of them. Money attributes in two
currencies are refused (`currency_mismatch`). Every template reads each attribute in
one direction (`test_every_template_reads_each_attribute_in_one_direction`).

### 24.6 Idempotency

A build's identity is the content digest (`sha256:` and the SHA-256 of the canonical
JSON) of everything it is built from (`builder.build_document`): the builder
(`mythos.economics.scenario-builder/v2`, `builder.BUILDER_VERSION`; `v1` until grouping
`v2`), grouping and pack
versions and the window; every template version; the deployment; the
parameter-set version's key, number and content digest; the currency and as-of date;
every effect as resolved, with its observation, SPINE effect, time and every
attribute; and every finding link and role. The title and the scenario superseded name
the draft and are not in it. `ScenarioBuild` holds the digest, unique per deployment
(`uq_econ_build_digest`):

- the same inputs, in any order, by anyone, return the scenario already built (200,
  `created: false`) and write nothing: never a second;
- two builds of the same inputs racing past that lookup are refused by the
  constraint: the later answers 409 and writes nothing, since the whole build is one
  transaction;
- every row of a build is made, and every check of every row run -- the checks a
  save runs, each reading the build's own rows where a save reads stored ones -- and
  every component computed, BEFORE that transaction
  (`models.check_build_rows`); the atomic block only inserts
  (`models.insert_checked_rows`): one INSERT per row and no read
  (`test_a_builds_transaction_only_writes`). On SQLite, which takes its write lock at
  a transaction's first write, a stop's write waits for the inserts alone;
- any changed input -- an attribute's value or source, a finding or its role, the
  parameter-set version -- is a different digest and a new scenario
  (`test_the_digest_changes_with_every_input`);
- **the version records the deployment's SPINE system fingerprint as it is when it
  is built** (`assurance.fingerprint.compute_system_fingerprint`, in the
  `system_fingerprint` form of section 8: 64 lowercase hex;
  `builder.current_system_fingerprint`), read before the transaction, and the routes
  show it. One that cannot be computed, or is not in that form, is recorded as none,
  with the reason in fixed words (`system_fingerprint_unavailable`: "the system
  fingerprint could not be computed (<the fault's type>)", or "... is not in SPINE's
  form (64 lowercase hex)"): never one made up, and never a failed build
  (`test_a_fingerprint_that_cannot_be_had_is_recorded_as_none_with_the_reason`). The
  reason is shown on the card, which is the customer's, so a fault is named by its
  type alone -- its message can carry a SQL fragment, a path or a value -- and a value
  not in the form is never echoed (the lead's review of #157;
  `test_a_faults_message_is_never_recorded_or_shown`). The card's reading of the
  deployment's fingerprint at issue goes through the same words. A
  version records one or the other, never both (`field_malformed`). The fingerprint
  is NOT in the digest: it is the state the version was built in, observed, not
  something it is built from, so a rebuild of the same inputs after the deployment
  changed returns the version with the fingerprint it recorded, and writes nothing
  (`test_a_build_records_the_deployments_system_fingerprint`). What the build writes
  from its inputs is unchanged, so the builder stays `v2`.

A finding found later, which enables an effect already built, is a new build of the
inputs with it (superseding the earlier scenario, `supersedes`): its event has the
same key and the same components, with the finding beside the others, and the same
totals (`test_a_late_finding_joins_its_event_and_adds_no_component`).

### 24.7 The double-count invariant

Enforced in code and in the database, not by convention:

| Invariant | Holds by | Proven by |
|---|---|---|
| findings never multiply a loss | the grouping key names no finding; components are made once per event | `test_one_two_and_five_findings_on_one_effect_make_one_event_with_the_same_totals`, `test_findings_never_make_events_of_their_own` |
| one effect is one event | the effect type is not in the key; every observation of one SPINE effect is one unit, whatever the window; one SPINE effect declared two ways is refused (`spine_effect_inconsistent`); a CausalEffect whose SPINE effect is in another event of its scenario, or declared there another way, is refused on save (`duplicate_id`) | `test_two_effect_types_one_template_takes_on_one_asset_are_one_event`, `test_every_observation_of_one_spine_effect_is_one_event_however_far_apart`, `test_every_observation_of_one_spine_effect_is_one_plan`, `test_the_model_holds_one_spine_effect_to_one_event` |
| joined effects never understate | the larger loss at each point across all of an event's effects | `test_joined_effects_read_the_larger_loss_whatever_their_keys`, `test_an_observed_and_a_hypothetical_effect_take_part_alike`, `test_adding_an_effect_never_lowers_the_events_loss` |
| one effect is in exactly one loss event of its scenario version | `CausalEffect.loss_event` is one foreign key, not null; an effect key, and a SPINE observation, are unique within a scenario (`uq_econ_effect_key`, `uq_econ_effect_observation`), checked on save (`duplicate_id`) and by the database. A hypothetical effect takes part in every event of its key (grouping v2), but its one row, and its findings', is in the one event that prices it: it is one effect, and never an occurrence | `test_the_database_holds_an_effect_to_one_event`, `test_a_hypothetical_effect_no_longer_moves_when_an_effect_is_added` |
| a hypothetical effect's loss is counted once | `builder.price`: one event of its key reads its figures, at all three points, where it adds the most at base; every other event lists it, `joined`, and reads none of them | `test_a_hypothetical_effect_is_priced_once_however_many_events_its_key_has`, `test_the_route_prices_a_hypothetical_effect_once`, `test_adding_an_effect_never_splits_an_event_and_prices_a_hypothetical_once` |
| merging events counts a shared pool once | under grouping v2 an effect within 24 hours of two events makes them one, which reads each attribute at the larger loss ONCE: never below either event it merged, and not their sum | `test_merging_two_events_counts_their_shared_pool_once`, `test_adding_an_effect_never_splits_an_event_and_prices_a_hypothetical_once` |
| an effect two templates cover is assigned to one | `templates.select`, by precedence | `test_an_effect_two_templates_cover_is_in_one_event`, `test_an_effect_two_templates_cover_is_assigned_to_one_by_precedence` |
| two distinct effects are two events | different keys, or no chain of observations, each within 24 hours (inclusive) of the next, between them | `test_two_distinct_effects_make_two_events`, `test_the_window_joins_any_member_within_24_hours_and_a_hypothetical_joins_every_event`, `test_the_window_is_24_hours_inclusive_to_the_microsecond` |
| a rebuild duplicates nothing | the digest, unique per deployment | `test_a_rebuild_returns_the_same_scenario_and_writes_nothing`, `test_a_build_raced_by_the_same_build_is_409_and_writes_nothing` |
| market value stays apart | each event's market-value line is #146's (section 16); the scenario's totals sum gross cash and market value separately, and never one into the other | `test_market_value_is_reported_apart_and_never_summed_into_cash` |

The scenario's totals are each event's loss once, given it happens: the events are
distinct causal losses. They are not an annual figure; frequency is the probabilistic
engine's.

### 24.8 The routes

Mounted under `/api/assurance/` from `assurance/economics/scenario_api.py`, imported
GUARDED in a guard of its own (section 2):

| Route | Name | Does |
|---|---|---|
| `POST deployments/<uuid>/economics/scenarios/build/` | `deployment-economics-scenario-build` | builds a scenario draft: 201 with the scenario, its build and its events; 200 with the scenario already built from the same inputs; 409 on a race |
| `GET deployments/<uuid>/economics/scenarios/<scenario uuid>/events/` | `deployment-economics-scenario-events` | the scenario's system fingerprint as built (or none, and why: section 24.6), its review status (`draft` until a review is recorded, then the latest verdict, with every review), and its events, each with its template, grouping key, effects (every effect taking part, by when they occurred; from grouping v2 on, a hypothetical effect is listed in every event of its key, `joined: true` where its row is in another, the event that prices it, and its figures are read only there) and the findings enabling them, its components with their formula and, for every input, the template's source and the parameter read (the set's variable, with its version, the effect's attribute, or the event's larger-loss value with every effect attribute it was taken across), the gross cash loss, the loss net of the set's insurance where the set states a policy, and the market-value line apart; and the scenario's totals |

The body:

```json
{"title": "Payment agent: destination changed after approval",
 "parameter_set": {"set_key": "bank_prod_2026q4", "version": 1},
 "currency": "USD", "as_of": "2026-10-06",
 "effects": [{"key": "redirect", "origin": "observed", "observed_effect": "<the SPINE row's uuid>",
              "effect_type": "funds_transfer_altered", "asset": "<asset uuid>", "business_process": "payments",
              "attributes": {"success_rate": {"unit": "ratio", "low": "0.35", "base": "0.35", "high": "0.35",
                                              "source_type": "MYTHOS_OBSERVED",
                                              "evidence_ref": "7 of 20 attempts, observed as sha256:<the SPINE effect>",
                                              "effective_date": "2026-10-01"}}}],
 "findings": [{"finding": "<finding uuid>", "effect": "redirect", "role": "prerequisite"}],
 "supersedes": "<an earlier scenario's uuid, optional>"}
```

- **Authentication, tenancy and roles**, as the parameter-set routes' (section 19.3):
  a signed-in account (401); a deployment the caller cannot see, or a scenario of
  another deployment, is 404; only an admin or an analyst builds (403 for a viewer,
  even the owner), and anyone who sees the deployment reads. Every finding, asset,
  observed effect, parameter-set version and superseded scenario is looked up in the
  path's deployment only: another deployment's is not found, and the refusal does not
  say whether it exists elsewhere (`finding_not_found`, `asset_not_found`,
  `observed_effect_not_found`, `parameter_set_not_found`, `scenario_not_found`).
- **Author-recorded, and reviewed under section 7**: the draft names the signed-in
  account as its author, so its author never reviews it; another admin or analyst
  does, through `ScenarioReview`.
- **Strict JSON**: exactly the fields at every level, the 64 KiB cap (413 on the
  declared length, and the parser never reads past it), a key twice in one object and
  a bare `NaN` refused by the parser, the strict decimal-string rule for every value.
  A refusal is 400 with `code` and `detail`, and nothing is recorded. At most 50
  effects and 500 finding links.
- **Unavailable**: while economics cannot read its currency table, both answer 503
  and record nothing.
- **Not on a stop path**: both are in `safety.stops.NOT_STOPS`; the build writes
  nothing the decision reads (`tests/test_every_write_route_keeps_the_decision_current.py`).
  A builder or template module that will not import leaves these two routes unserved
  and nothing else: under `tests/economics_broken_builder.py`, the scan's Stop
  answers 202, `deliver_owed_stops` runs its checks and reaches its handler,
  `manage.py check` passes and the parameter-set routes are served
  (`test_a_builder_fault_never_takes_down_a_stop`).

The builder's refusal codes (`templates.REFUSALS`, raised as `BuildRefused`, a
`MoneyRefused`); a code the money or scenario engine already publishes
(`duplicate_id`, `field_unrecognised`, `field_missing`, `field_malformed`,
`unit_mismatch`, `not_decimal`, `date_malformed`, `date_inversion`, `currency_unknown`
and the rest) is raised as that engine's:

| Code | Refused |
|---|---|
| `effect_type_unrecognised` | an effect's type is one of the pack's effect types |
| `business_process_unrecognised` | an effect's business process is one of the pack's business processes |
| `origin_unrecognised` | an effect is observed (a SPINE observed effect) or hypothetical (declared) |
| `finding_role_unrecognised` | a finding enables an effect as a prerequisite, an amplifier or an alternate path |
| `attribute_unrecognised` | an effect states only the pack's attributes, each in its unit |
| `effect_key_malformed` | an effect's key is 1 to 60 characters: lowercase ASCII letters and digits, '-' and '_', starting with a letter or digit |
| `effect_out_of_scope` | no template of the pack covers the effect's type on its business process |
| `effect_not_declared` | a finding names an effect the build does not declare |
| `effect_without_finding` | a hypothetical effect rests on at least one finding that enables it; an observed effect rests on its signed observation |
| `observed_source_on_hypothetical` | an attribute of a hypothetical effect is never MYTHOS_OBSERVED: nothing was observed; declare the effect observed, naming the SPINE observed effect, or give the attribute's real source |
| `observed_source_not_observable` | MYTHOS_OBSERVED is only a rate, a count or a duration an assessment observes; a money amount or a market figure is CUSTOMER_PROVIDED, EXPERT_ESTIMATE or another source that is not an observation |
| `observed_source_unbound` | a MYTHOS_OBSERVED attribute's evidence_ref is the observed effect it came from: its SPINE effect digest, alone or followed by a space and a note (a digest that is only mentioned, or that follows other text, binds nothing) |
| `spine_effect_inconsistent` | every observation of one SPINE effect is declared with one effect type, asset and business process: one effect is one loss event |
| `observed_effect_not_found` | the observed effect is not one of this deployment's SPINE observed effects |
| `observed_effect_not_in_force` | the SPINE observed effect does not stand: its signature does not verify now, it is not signed by an observed-effect key, or its evidence is not the document its signature names |
| `finding_not_found` | the finding is not one of this deployment's findings |
| `asset_not_found` | the asset is not one of this deployment's assets |
| `parameter_set_not_found` | the customer parameter-set version is not one of this deployment's |
| `scenario_not_found` | the scenario superseded is not one of this deployment's |

### 24.9 Limitations, and decisions for the owner

- **One SPINE effect is one effect.** Two effects with distinct SPINE effects on one
  key are distinct effects, and join one event only through the window; a test
  campaign that observes the same workflow and tool twice is one effect however far
  apart, but two DIFFERENT tools more than 24 hours from each other, with no effect
  of the key between them, are two events.
- **The window is a fixed 24 hours from ANY member of an event** (grouping v2; v1
  measured it from the event's first observation), for distinct effects of one key.
  A chain of effects, each within 24 hours of the next, is one event however long it
  runs.
- **Hypothetical effects have no time**: within one key they make one event, or take
  part in every observed event of the key (grouping v2; v1 joined them to the first).
- **Monotonicity holds per event, not per scenario** -- under grouping v1. RESOLVED in
  grouping v2 by the owner's decision of 12 Oct 2026 (decision 12), as below. Under
  v1, adding an effect to an event never lowered that event's loss (section 24.5), but
  adding an effect to a build could regroup a scenario's events -- an event's members, the window's anchor and the event
  a hypothetical effect joins all depend on the whole set of effects -- and a regrouped
  scenario can state a LOWER gross than before. Two cases (every other attribute the
  same in each; figures are success rate and exploitable window; the gross cash loss
  at low / base / high):
  - **A hypothetical effect moves.** One payments key. O1 is observed (0.9, 0.1 hours)
    and H is hypothetical (0.1, 20 hours). H has no time, so it joins the key's first
    event, O1's: one event at the larger loss across the two (0.9, 20 hours), and the
    scenario's gross is 16,877,000 / 59,064,500 / 101,252,000. Add O2, observed 29
    hours BEFORE O1 with a different tool (0.1, 0.1 hours). O2 now opens the first
    window and O1, 29 hours later, falls outside it; H joins the key's first event,
    now O2's. Two events: O2 with H (0.1, 20 hours: 6,564,500 at base) and O1 alone
    (0.9, 0.1 hours: 297,312.50 at base). The gross falls to 1,963,375 / 6,861,812.50 /
    11,760,250: the base falls from 59,064,500 to 6,861,812.50 by adding an effect.
  - **The window moves.** One payments key. O1 (0.9, 0.1 hours) and O2 (0.1, 20 hours)
    are observed 20 hours apart, with different tools: one event at the larger loss
    (0.9, 20 hours), the same 16,877,000 / 59,064,500 / 101,252,000. Add U0 (0.1, 0.1
    hours, a third tool) observed 10 hours BEFORE O1. The window now opens at U0; O1,
    10 hours in, joins it; O2, 30 hours in, opens another. Two events -- U0 with O1
    (297,312.50 at base) and O2 alone (6,564,500) -- and the same fall, from 59,064,500
    to 6,861,812.50 at base.

  Each event was still the larger loss of its effects, and a build still
  deterministic and repeatable; what v1 did not hold is that a build stating more
  effects states at least the gross of one stating fewer. Options for the owner:
  **(a)** a hypothetical effect joins every event of its key, not only the first, so
  which event is first no longer decides where it lands; **(b)** re-anchor the window
  -- join any effect within 24 hours of ANY member of an event, not of its first --
  so adding an effect can merge events but never split one; **(c)** accept it and
  disclose it, as v1 did. Merging two events still counts their shared pool once
  (section 24.5), so even with (b) a scenario can state less than the sum of the
  events it merged, by design, but not less because an event was split. The
  recommendation was (a) and (b) together, and the owner adopted it on 12 Oct 2026:
  grouping v2 (`mythos.economics.grouping/v2`, builder
  `mythos.economics.scenario-builder/v2`) implements both.

  **Priced once (review of #154).** As first built, v2 read a hypothetical effect's
  figures in EVERY event of its key, so its loss was counted once per event: H (0.9,
  20 hours; 59,064,500 at base alone) with two (0.1, 0.1 hour) observed events 48
  hours apart stated 118,129,000, H twice, and with five events H five times. On the
  lead's call (12 Oct 2026, under the owner's "go with recommendations"), a key's
  hypothetical effects are now PRICED in ONE event, for all three points: the event
  where they add the most at base (ties: high, then low, then the earliest). Every
  other event lists them, `joined`, and reads none of their figures (section 24.5).
  That case is now 16,888,375 / 59,099,312.50 / 101,310,250: H once, plus the other
  event's own (0.1, 0.1 hour) loss
  (`test_a_hypothetical_effect_is_priced_once_however_many_events_its_key_has`,
  `test_the_route_prices_a_hypothetical_effect_once`).

  Under v2 both cases keep their gross. In the first, H takes part in both events and
  is priced in O1's, where its window adds the most: O1's still reads (0.9, 20 hours),
  O2's its own (0.1, 0.1 hours), and the gross RISES to 16,888,375 / 59,099,312.50 /
  101,310,250 (`test_a_hypothetical_effect_no_longer_moves_when_an_effect_is_added`).
  In the second, U0 is within 24 hours of O1, and O1 of O2: one event, at the same
  16,877,000 / 59,064,500 / 101,252,000
  (`test_an_added_effect_no_longer_moves_the_window`).

  What v2 holds, property-style over 300 random sets of effects on one key, each with
  one effect added (a fixed seed; no database:
  `test_adding_an_effect_never_splits_an_event_and_prices_a_hypothetical_once`):
  adding an effect never splits an event or moves an effect; a hypothetical effect
  is priced once, before and after; and the scenario's gross never falls at BASE
  unless the added effect merges events. **At high and low it can**: where the
  added effect makes another event the one where the key's hypothetical effects add
  the most at base, they leave the event where they added more at high (or low). In
  the 300 cases the gross fell at high twice and at low never, and at base never,
  outside a merge; the test pins those counts, so a fall at base fails it. A merge
  counts the merged events' shared pool once, by design (section 24.7): two (0.9, 20
  hour) effects 30 hours apart are two events of 59,064,500 at base each, and a third
  between them makes one event of 59,064,500, not their sum
  (`test_merging_two_events_counts_their_shared_pool_once`). So a scenario can state
  less after an effect is added where that effect shows that two events were one
  loss, never less than the largest event it merged (in the 300 cases, 11 merge, and
  8 of those state less), or, at high or low only, where it moves the pricing.

  **Alternative, a possible follow-up: price per point at the scenario level.** No
  event reads a hypothetical effect's figures; the scenario's totals add, for each
  key and each point separately, the most its hypothetical effects add to any one
  event of the key (that event's loss with them less its loss without them). That
  never falls at any point outside a merge (0 of the 300 cases), but the events
  would no longer carry the hypothetical loss, and the step 7b simulation (section
  25) would need the same rule per draw, a per-draw maximum over each event with and
  without them. Pricing per point WITHIN the events is not possible: of the property
  test's sets (before and after the added effect) with a hypothetical effect and two
  or more events, 78, the event gaining most differs between points in 21, and in 11
  of those an event read with the hypothetical effects at one point and without them
  at another would state a low above its base (`range_inverted`).
- **An attribute an effect does not state takes no part** in its event's larger
  loss: the others' value stands, and where none states it the component is unknown.
- **One SPINE effect to one event is held by the builder and by `CausalEffect`'s
  check on every save, not by a database constraint**: an observation of one effect
  is a row of its own (its key, its observation, its attributes), so a unique
  (scenario, SPINE effect) constraint would refuse the second observation itself.
- **A rebuild by another person returns the first author's draft.** The digest is the
  inputs', not the author's; that person did not author it and may review it.
- **Nothing is normalized here.** Every money parameter a build reads is in its
  currency already (`currency_mismatch` otherwise); FX and the cost index (section 12)
  are a later step's.
- **The window, the precedence, the larger-loss rule and the attribute vocabulary are
  this version's**; a change to any is a new grouping, pack or template version. The
  versions stayed `v1` through review round 1 (nothing was ever built under the
  unmerged first draft); the grouping and the builder are `v2` since the owner's
  decision of 12 Oct 2026 (decision 12), and the pack and its templates stay `v1`. A
  build recorded under grouping `v1` reads as it was built: its digest names `v1`, and
  its events list a hypothetical effect only in the one event it is recorded in.
- **Not modelled**: loan or underwriting agent error and model drift, the other two
  banking families; claims and authority edges as graph nodes (they are read, not
  linked); controls and mitigations (section 21 of the owner's specification, a later
  step). The system fingerprint on the built scenario, listed here before, is
  recorded since step 8's follow-up (section 24.6).

Decisions this version takes, which the owner may change (each with the alternative
not taken):

1. The six templates are the six families above; loan/underwriting error and model
   drift are left for a later pack version.
2. The grouping window is 24 hours (inclusive) from ANY member of an event, and an
   effect with no time takes part in every event of its key and is priced in the one
   where it adds the most at base (grouping v2, decision 12; v1 measured the window
   from an event's first observed effect, and joined an effect with no time to its
   key's first event).
3. The precedence is the order above, so an approval bypass on payments is a payment
   loss and on fraud/AML a workflow failure.
4. An observed effect counts only while its signature verifies now; one that does not
   is refused, never built as observed.
5. Customer figures dominate: transactions per day, the average transfer, recovery,
   labour rates and the notification costs come from the parameter set, never from
   the effect; what the parameter set does not hold (a window, a lump-sum range, an
   affected population) comes from the effect's declared attributes, each with its
   source.
6. **One effect is one event** (review round 1, the lead's interim call). The grouping
   key is the template, the asset and the process -- not the effect type, which the
   template encodes; every observation of one SPINE effect joins one event regardless
   of the window; one SPINE effect declared two ways in one build is refused.
   Alternative: keep the effect type in the key and let precedence alone decide the
   template, accepting two events (and a doubled transaction pool) for two types on
   one asset.
7. **Database backing for one SPINE effect, one event** is the model's check on save
   (`duplicate_id`), plus the existing unique effect key and unique observation per
   scenario. Alternative: one `CausalEffect` row per SPINE effect, with its
   observations as child rows, which a conditional unique (scenario, SPINE effect)
   constraint would then hold in the database itself -- a larger change to the graph.
8. **Joined effects read the larger loss** at each point, per the input's direction,
   across all the event's effects, observed and hypothetical alike, as a CALCULATED
   parameter citing each (`derived_from`). Alternatives: the lead effect's attributes
   (the first draft: understated, and dependent on key spelling), or a widened range
   (lowest low to highest high), which would lower the low point.
9. **A source-restricted input keeps its source** when merged: two customer churn
   figures make a value that stays CUSTOMER_PROVIDED (each point is one of them,
   unchanged), and a refused source takes no part while an accepted one does.
   Alternative: always CALCULATED, which the churn input refuses -- the customer-loss
   component would turn unknown as soon as a second effect stated a churn rate.
10. **MYTHOS_OBSERVED is only observable attributes** -- the success rate, the
    exploitable window, the affected customers, the missed cases, the repeat count and
    the outage's length -- and its evidence is its SPINE effect digest, exactly (alone, or then a space and a
    note), not a substring. A money amount (even one effect's size,
    `loss_per_event`) and a market figure are never observed. Alternative: let an amount the signed document carries be observed,
    once the observed-effect document carries amounts; today it carries none.
11. **The transaction only inserts**: every check runs before it, against the build's
    own rows. Alternative: keep each save's own checks inside the transaction (as
    the first draft did), holding SQLite's write lock while they read.
12. **Monotonicity per scenario** (review round 2; an owner decision, TAKEN on 12 Oct
    2026). Grouping v1 took (c), accept and disclose: monotonicity held per event, not
    per scenario. The owner adopted the recommendation, (a) and (b) together: (a) a
    hypothetical effect joins every event of its key; (b) join any effect within 24
    hours of ANY member of an event. They are a new grouping version,
    `mythos.economics.grouping/v2`, built by `mythos.economics.scenario-builder/v2`,
    not a change to v1, whose builds read as they were built. A key's hypothetical
    effects are priced in ONE event, where they add the most at base (the lead's
    call on the review of #154). Adding an effect now never splits an event or moves
    an effect, and lowers the scenario's gross at base only by merging events, which
    count a shared pool once; at high or low it can also fall where the pricing
    moves (the limitation above). Alternatives not taken: (c), as v1; pricing per
    point at the scenario level, a possible follow-up (the limitation above).

## 25. Wiring the simulation (MVP step 7b)

Phase E2, MVP step 7b: step 7a's seeded sampler (section 23) wired to step 4's
formulas and loss model (sections 14 to 18), over a scenario version the builder
(section 24) recorded. Per draw, every parameter a known component reads is sampled,
every component is evaluated, the components are summed to their event with cash and
market value kept apart exactly as step 4 keeps them, the event's insurance policy
is applied to the event, and the events are summed to the scenario. No route is
added: step 6 serves reports and scenario endpoints.

| | |
|---|---|
| Code | `assurance/economics/engine/scenario_simulation.py` (the wiring, pure) and `assurance/economics/engine/twins.py` (the formula twins, pure); `assurance/economics/simulation_service.py` (the thin Django service); `FinancialParameter.distribution` and `SimulationResult` in `assurance/economics/models.py`; migration `0064_parameter_distributions_and_simulation_results.py` |
| Tests | `tests/test_economics_scenario_simulation.py` (no database) and `tests/test_economics_simulation_service.py`; the safety tests of section 23.10, extended to the three new modules |

### 25.1 The parameter-to-distribution rule

`mythos.economics.parameter-distribution/v3` (`scenario_simulation.RULE_VERSION`; v3 is step 6's two-sided test),
`scenario_simulation.resolve`. Every parameter a run reads draws from exactly one
distribution, decided by this rule and recorded with the run (`parameters.<name>.rule`):

1. **Stated.** A `FinancialParameter` may carry a distribution (`distribution`, a
   nullable JSON column): a step-7a catalogue id, that distribution's version and its
   native parameters as decimal strings in the one spelling, and, for an expert range,
   whether the data are sparse:
   `{"id": "lognormal", "version": 1, "params": {"mu": "9.2", "sigma": "0.8"}}`. It is
   read exactly (`distribution_malformed`, `distribution_unknown`,
   `distribution_version_unknown`), built by step 7a's catalogue with all of its checks
   (an expert range takes the parameter's own `source_type`, never one it states), and
   refused unless it draws only what the parameter's unit holds
   (`distribution_not_for_unit`): a ratio from a rate (Beta) or an expert range inside
   [0, 1]; a count from a count, severity or expert distribution; any other unit from a
   severity distribution or an expert range at or above zero. It must also **hold the
   row's own figures** (`check_fits_range`, `distribution_contradicts_range`, naming the
   test it failed), each figure compared as the binary64 the run draws (the
   frequency's mean exactly). How depends on what the figure is.

   **Every stated distribution but the frequency's** -- a severity, a rate, an expert
   range, and a count stated on any other count row (an observed repeat count, a
   number of affected customers: the count itself) -- describes the figure itself, so
   it holds the row **from both sides**, four tests in this order (`RANGE_TESTS`):
   - `support`: the low and the high inside the closure of its support (a lognormal or
     gamma from 0 up; a rate from 0 to 1; a PERT or triangular from its minimum to its
     maximum; a generalized Pareto from its threshold, up to `threshold - scale/shape`
     where the shape is negative; a splice from 0 to its tail's end; a count from 0 up);
   - `base`: the base between the distribution's P5 and P95 (`RANGE_FIT_PERCENTILES`);
   - `median`: its median between the low and the high, low <= P50 <= high, both
     included;
   - `mass`: at least `RANGE_MASS_FLOOR` (0.5, one constant) of its mass between the
     low and the high, both included: P(low <= X <= high) >= 0.5 (`mass_between`; a
     count's mass is that of the whole numbers in the range).

   And it is stated only on a range: a row whose low, base and high are one figure is a
   point mass (rule 2), and a distribution stated on it is refused
   (`distribution_on_fixed_row`), a count on a fixed count row included (review round
   1, MEDIUM-1: the reviewer's ZIP(0.5, 6) on an observed repeat count of 3 / 3 / 3,
   half of whose draws said the effect never repeated, was built and drawn from). The
   first two tests alone were one-sided: a gamma whose median lies far below the row's
   low held a base below its P95 and a low inside its support, and fitted. A
   lognormal(0, 1) stated on 100,000 / 200,000 / 400,000 would run with a mean of
   1.63; a gamma of shape 0.2 and mean 25,000 on 20,000 / 25,000 / 32,000 has its
   median at 2,593. Each is refused, and the refusal names the test it failed, the
   parameter and its figures, and the distribution's support, P5 to P95, P50 and mass
   in range, each in its shortest round-trip spelling (review round 1, NIT-1: a mass of
   0.49995 is printed so, never as 0.5), so the conflict is surfaced, never resolved by
   silently taking one (owner's specification, section 27). The bounds are inclusive:
   Triangular(0, 1, 2) on 1 / 1.5 / 2 has its median at the low and exactly half its
   mass in range, and holds; on 1 / 1.5 / 1.99 it is refused
   (`test_the_floor_and_the_median_are_inclusive`).

   **The frequency** (the parameter named `frequency`, which `resolve_frequency`
   checks; it states a Poisson, negative binomial or zero-inflated Poisson) is another
   matter. Its row's low, base and high are **values of its rate**, which the formulas
   multiply (events a year), and its count distribution says how the count varies from
   year to year GIVEN the rate, and how uncertain the rate is. The count's yearly
   spread is not compared with the row; **the rate its count implies** is
   (`implied_rate`):
   - a Poisson(lambda): the rate lambda, a point;
   - a negative binomial (numpy's size r and probability p, failures before the r-th
     success): a Poisson whose rate is **Gamma(size, (1 - p) / p)** -- shape r, scale
     (1 - p) / p -- the Gamma-Poisson mixture, whose mean r (1 - p) / p and variance
     r (1 - p) / p^2 are the negative binomial's;
   - a zero-inflated Poisson(pi, lambda): a rate of 0 with probability pi, and lambda
     otherwise (a point where pi is 0).

   It is held to five tests in this order (`FREQUENCY_RANGE_TESTS`):
   - `support`: as above (from 0 up);
   - `rate`: the count's mean between the low and the high, compared EXACTLY, the mean
     computed from the stated decimal parameters by its closed form (`exact_count_mean`:
     lambda; r (1 - p) / p; (1 - pi) lambda; review round 1, LOW-2: ZIP(0.7, 1)'s mean is
     0.3, which binary64 makes 0.30000000000000004, above a high of 0.3);
   - `base`: its base at or above the count's P5 and below the count after its P95
     (round 2: a count's percentiles are whole numbers and its base a rate; a Poisson
     rarer than once in twenty years has a P95 of 0 and holds a base of its own rate,
     `test_a_rare_count_holds_its_own_rate`). Kept because it refuses what the rate
     test does not: a base far from the mean while the mean is still in range, as
     0 / 1 / 2 stating Poisson(0.02) (rate 0.02, P95 count 0, a base of 1) or 0 / 10 /
     20 stating Poisson(1) (P95 count 3, a base of 10)
     (`test_round_2s_base_rule_refuses_what_the_rate_test_does_not`);
   - `rate_median`: the implied rate's median between the low and the high (a
     Gamma's P50; a zero-inflated Poisson's is 0 where pi is at least one half);
   - `rate_mass`: at least `RANGE_MASS_FLOOR` of the implied rate between the low and
     the high, both included (exact for a point, and for a zero and a point).

   The last two are review round 1's MEDIUM-2: bounding the mean alone reopened the
   one-sided hole for an over-dispersed count. A negative binomial of mean 1,200 on
   1,000 / 1,200 / 1,400 holds the mean test at every size, but at size 0.1 its rate's
   median is 7 a year and only 2.5% of its rate lies in range; sizes 0.1, 0.3 and 1 are
   refused by the rate's median (7, 293, 832), size 10 by its mass (40%), and sizes 50
   and 100 hold (76% and 91%) (`test_the_frequencys_figures_bound_the_rate_its_count_implies`).
   So Poisson(5) on 4 / 5 / 6 holds (its rate is 5, though only 49.7% of a year's count
   falls in 4 to 6), and so does Poisson(0.05) on 0.01 / 0.05 / 0.2 (no whole number
   lies in that range, which says nothing about the rate); Poisson(4) on 1 / 2 / 3 is
   refused (its rate, 4, is above the high), as is a negative binomial whose mean lies
   above the high, and a zero-inflated Poisson(0.5, 4) on 1 / 2 / 4 (its rate is 0 in
   half its years). **A fixed rate is a Poisson of that rate**: 2 / 2 / 2 with
   Poisson(2) is a rate known exactly whose count still varies, and the rate test asks
   that its mean be exactly that figure, so Poisson(3) on 2 / 2 / 2 is refused; a count
   whose implied rate is not that point (a negative binomial, or a zero-inflated
   Poisson with pi above 0: ZIP(0.7, 1) on 0.3 / 0.3 / 0.3, whose mean is 0.3) states
   the rate uncertain, which a fixed row denies (`distribution_on_fixed_row`). The row
   is checked when it is written, with the engine's code (`EngineRefused`), and stored
   in the one spelling; it is checked again when a build names its version and when it
   is run, by the same function, and the refusals agree word for word (section 19.4).
2. **A point mass** where it states none and its low, base and high are one figure.
   A point mass draws nothing.
3. **PERT(low, base, high)**, weight 4, where it states none, its values are a range,
   and its `source_type` is `EXPERT_ESTIMATE`: the only source step 7a's rule lets an
   expert range stand for without a sparse mark (section 23.1). It is listed among the
   run's expert parameters.
4. **Otherwise refused**, `no_admissible_distribution`, naming the parameter, its range
   and its source: a customer's, a benchmark's, an observed or a calculated range never
   becomes a PERT silently. Its distribution must be stated. Only low = base = high is a
   point mass: low = base < high (or low < base = high) is a range.
5. **A derived parameter** (`derived_from`, the scenario builder's larger loss of an
   event's attribute across its effects, section 24.5) draws from its contributors
   (`resolve_derived`, rule `derived_larger_loss`): each contributor by rules 1 to 4
   (stated, point mass, PERT for an expert, or refused), each from its own stream, and
   per draw the value giving the larger loss in the direction of the inputs that read
   it (the highest where they increase the loss, the lowest where they decrease it), as
   the builder takes it per point. Two point masses make a point mass at the larger,
   exactly. A contributor that is refused refuses the merge, with its code and naming
   it. A PERT of the merged range is not used: a PERT of pointwise maxima need not
   bound the expected maximum. A derived parameter states no distribution of its own,
   and its low, base and high must be the larger loss of its contributors' at each
   point (`derived_malformed` otherwise, at write time as at run time).

A scenario's frequency (section 25.5) is the exception: it must state a count
distribution (`frequency_distribution_missing`, `frequency_not_a_count`); nothing
defaults, since a PERT is not a count.

### 25.2 What is shared and what varies

`mythos.economics.variation/v2`. Section 23.11 left open how uncertainty about what a
parameter IS is separated from variation between events; this step separates them:

- **Shared** (the default), drawn once per simulated year and the same for every
  occurrence of that year: every parameter, the customer parameter set's variables,
  the policy's terms, the frequency and an effect's attributes (the window, the
  affected population, a lump-sum range) alike. A range is uncertainty about what the
  figure is, and a wide one moves whole years together.
- **Per occurrence**, drawn afresh for each occurrence: only a parameter the run's
  input names (`ScenarioInput.per_occurrence`; each parameter's `variation` in the
  canonical inputs, so it enters the input digest), for a figure known to vary from
  one occurrence to the next. A derived parameter's contributors are drawn as it is.
  Nothing names one yet (section 25.9).

The trade-off (section 25.10): drawn per occurrence, N occurrences of one range average
out within a year and the annual tail narrows. For an expert lump sum of 10,000 /
100,000 / 1,000,000 and Poisson(5) events a year, per occurrence gives an annual P95 of
2.32M and a P90 of 2.02M; once a year gives 3.18M and 2.52M, with the same mean
(`test_an_effects_range_is_drawn_once_a_year_unless_named_per_occurrence`). Where a
range is uncertainty about the figure, per-occurrence drawing understates the tail by
27%; where it is genuine variation between occurrences, once a year overstates it.

Without a frequency a draw is one occurrence, and the two coincide. Each parameter's
draws come from step 7a's sub-stream of its own stream name (`stream_name`: `p` and 40
hex digits of the SHA-256 of `mythos.economics.parameter-stream/v1`, a zero byte and
the parameter's name), so they depend on the seed and the name only: adding a
parameter changes no other's draws, and a shared parameter's yearly draws are the very
draws it makes without a frequency.

### 25.3 The formula twins

`engine/twins.py`, `TWINS_VERSION` 1. Every formula of the catalogue has a vectorised
twin, keyed by the same id and version: the same expression in binary64 over arrays of
draws. The Decimal formula stays the source of truth. A formula with no twin is
refused by name (`twin_missing`); nothing is approximated. The tolerance is
`RELATIVE_TOLERANCE`, **1E-13** relative: `|twin - formula| <= 1E-13 x |formula|`, the
formula evaluated in Decimal at the very binary64 values the twin read, and exactly
zero where the formula is zero. A twin makes at most six roundings (about 7E-16), so
the margin is over a hundredfold. No twin calls `exp`, `log` or `pow`, so a twin's
result is the same on every IEEE-754 platform. **The tolerance holds for normal
binary64 results only**: below 2.2E-308 (the smallest normal) a product may underflow
to a subnormal, which keeps fewer significant bits, so the relative error grows
(`per_affected(1E-160, 1E-160)` is 1.1E-5 off). No real input reaches it: a money
amount, a count or a duration that small is not a loss.

| Formula | Version | Tolerance | Known-answer points | Random points |
|---|---|---|---|---|
| `repeat_loss` | 1 | 1E-13 | 6 | 6,000 |
| `repeat_in_window` | 1 | 1E-13 | 6 | 6,000 |
| `interruption` | 1 | 1E-13 | 3 | 6,000 |
| `fixed_plus_hours` | 1 | 1E-13 | 24 | 6,000 |
| `per_affected_plus_fixed` | 1 | 1E-13 | 6 | 6,000 |
| `per_affected` | 1 | 1E-13 | 3 | 6,000 |
| `support_contacts` | 1 | 1E-13 | 9 | 6,000 |
| `capped_credit` | 1 | 1E-13 | 3 | 6,000 |
| `replacement_share` | 1 | 1E-13 | 0 | 6,000 |
| `churned_margin` | 1 | 1E-13 | 0 | 6,000 |
| `premium_increase` | 1 | 1E-13 | 0 | 6,000 |
| `lump_sum` | 1 | 1E-13 | 30 | 6,000 |
| `share_price_reaction` | 1 | 1E-13 | 0 | 6,000 |

The known-answer points are every known component of step 4's two worked examples and
the six templates' worked examples, at low, base and high, against the Decimal result
at the Decimal inputs (90 in all). The random points are 2,000 at each of three fixed
seeds, log-uniform from 0.001 to 1E9 for amounts, counts and durations, uniform on
[0, 1] for ratios, with 0, 1, 0.5 and 0.95 always among them (the complement's ends
and Sterbenz's range), and for `capped_credit` the cap a quarter of, equal to and four
times the uncapped credit, so both sides of the clip are tested more than a thousand
times. Every twin is also shown monotone in each input in the direction the formula
declares (1,000 points per input), and the complement and the cap exact.

**Exact where nothing is uncertain.** A component whose every input is a point mass is
computed once, by its Decimal formula (`evaluated_by: decimal_constant`). An event whose
every known component is so, and whose policy's terms are point masses, has its gross
cash, market value, recovery and retained cash from step 4's own Decimal `assess`; a
scenario whose every event is so has their Decimal sums. Each such value, as the nearest
binary64, is the same in every draw, and its summary (P10, P50, P90, mean,
severe-but-plausible and every band) is the Decimal value itself, written in full, with
a standard error of zero; the record says `evaluated_by: decimal_constant` for the
event and the scenario. The invariant checked is that every draw is that value: 7a's
mean of a constant vector (`fsum / n`) can round one ulp off it, which is neither a
draw of another value nor a reason to refuse the run
(`test_an_exact_line_completes_whatever_the_draws_or_the_seed`). So a run whose parameters are all point masses reproduces step
4 to the last digit: 100.10 + 200.20 is 300.30 (binary64 sums it to
300.29999999999995), and `repeat_in_window` at 100 a day is step 4's 60-digit Decimal,
which binary64 cannot hold
(`test_a_run_with_nothing_uncertain_is_step_4_to_the_last_digit`); and for each of step
4's known-answer fixtures and the six templates, each parameter collapsed to the value
step 4 reads at low, base or high (a decreasing input's high at the low), the run's
figures are step 4's (`test_degenerate_distributions_reproduce_step_4_exactly`, 24
cases). A year's sum in a compound run is a binary64 sum of N such values, as any
other.

### 25.4 The aggregation order

Per draw, in this order, all in binary64:

1. each known component, by its twin (or its Decimal constant); an unknown component
   has no amount and is excluded, never zero, so its event and the scenario are
   `complete: false` and read "at least", as in step 4;
2. each event's **gross cash**, the sum of its cash components in component order, and
   apart from it its **market value**, the sum of its market-value components: never
   one into the other (`never_added_to_cash`);
3. **insurance per event**: step 4's policy (section 17), applied to each event's own
   gross components, once per occurrence: each covered family summed and capped at its
   sublimit, the deductible off their total, the recovery capped at the limit and never
   above the gross. The retention and the sublimits apply to each event,
   **never to a year's sum or to the scenario's sum**
   (`test_the_retention_is_applied_per_event_never_to_the_years_sum`,
   `test_the_sublimit_is_applied_per_event_never_to_the_years_sum`, exact per year);
4. the scenario's lines: the events' gross cash, market value, recovery and retained
   cash, each summed in event order;
5. with a frequency, each line's years: step 7a's `compound_annual`.

Components sum to their event and events to the scenario per draw, bit for bit, not
only in summary (`test_components_sum_to_their_event_and_events_to_the_scenario_per_draw`),
except where a line is exact (section 25.3): there the line is step 4's Decimal sum as
the nearest binary64, which the binary64 sum of its parts may miss by its rounding.
The simulation adds no event and counts none twice: its events are exactly the
scenario version's, an event key twice is refused (`duplicate_id`), and an occurrence
realises every event once.

**The limit is read per event, as step 4 reads it.** A policy's limit is an aggregate
limit; reading it per event lets a year's recoveries, summed over its events, exceed
it, which can understate the retained loss. The run measures how often:
`aggregate_limit_exceeded_share` is the share of draws (of years) whose summed
recoveries exceed the limit. A yearly aggregate cap is a decision for the owner
(section 25.10).

Every line is summarised by step 7a's `summarize` (section 23.5): P10, P50, P90, the
mean with its standard error and band, the percentile bands and the
severe-but-plausible percentile (P95 unless the run states another), with the
invariants checked, and written as decimal strings (section 23.6). A line whose inputs
include an infinite mean or variance reports no mean or no standard error, naming them.
The record gives the scenario's gross cash, retained cash (under a policy; the
headline then) and market value; each event's; and each component's.

### 25.5 Frequency

A scenario has a frequency where the parameter-set version it was built from states
one (section 19.4), or where it holds a parameter of its own named `frequency`: a
count of events a year stating a count distribution. Both at once is a conflict,
refused (`duplicate_id`), never resolved by taking one. Then a draw is a simulated year of N
occurrences, N from the frequency's own stream (`@frequency`), each occurrence every
event of the scenario once, and the year's loss the sum of its occurrences'
(`compound_annual`); the basis is `annual_loss`, each line's **expected annual
exposure** is its mean, and the scenario's per-occurrence distribution is summarised
beside it (`per_occurrence`). Its mean is E[N] times the per-occurrence mean, within
four standard errors (`test_the_expected_annual_exposure_is_the_frequency_times_the_severity`).

Without one, a run is **one occurrence per draw**: every event once, each given it
happens (section 24.7), basis `per_occurrence`, and there is no expected annual
exposure; the record says so rather than guessing a year.

### 25.6 The stored result

`SimulationResult`, append-only like every economics record, with no account column,
going with its deployment:

| Field | Holds |
|---|---|
| `scenario`, `deployment` | the scenario version run, and its deployment (`cross_tenant_reference` otherwise) |
| `seed`, `draws`, `severe_percentile` | the seed as text (0 to 2^64 - 1: wider than a signed 64-bit column, never a double), the draws, the percentile |
| `inputs`, `input_digest` | the canonical inputs (below) and `sha256:` of their canonical JSON |
| `versions` | every version the figures rest on: the wiring, the rule, the variation, the twins and their tolerance, each formula, each catalogue distribution, the sampler, the bit generator, the stream domains, numpy; and every limit that decides a recorded refusal (`limits`: the values and events budgets, the largest sample and count mean, the generalized Pareto's shapes, a splice's body share, the largest standard exponential, the range-fit percentiles and mass floor) |
| `record`, `summaries`, `result_digest` | the whole record (schema `mythos.economics.scenario-simulation/v1`) and its digest; its scenario and event figures as decimal strings |
| `status`, `refusal_code`, `refusal_detail` | `completed`, or `refused` with the code; never both (a check constraint) |
| `started_at`, `finished_at`, `duration_ms` | the timing, outside both digests |

The canonical inputs are every event and component with its formula and the parameter
each input reads; every parameter with its values, unit, currency, source, evidence,
dates, **stated distribution** and variation; each derived parameter's contributors;
the policy's terms and exclusions; the frequency; the severe-but-plausible percentile;
the rules; and every version and limit. They hold
neither the seed nor the draws, which are columns of their own. Nothing in a result is
a float (`result_malformed`), and both digests are recomputed on save
(`digest_mismatch`).

**Idempotent.** One row per scenario version, input digest, seed and draws
(`uq_econ_simulation_inputs`): the same inputs return the row already recorded and
never run or write a second. Every check of the row, its lookup of the same identity
included, runs before the transaction, which only inserts (`insert_checked`, refused for
a row not checked or changed since): two runs racing past that lookup are stopped by the
constraint (`IntegrityError`), and the later returns the first's row
(`test_a_row_that_lands_between_the_check_and_the_insert_is_returned`). A version change
(numpy included) or a limit change is a new input digest, so a new row, never an old one
returned: a refusal recorded at a lower values budget is not returned at the default
(`test_a_refusal_under_a_lower_limit_is_not_returned_under_the_default`). The same
seed gives the same digests, a different seed a different result digest, and two
interpreters with different `PYTHONHASHSEED` the same.

A refusal the inputs decide (no admissible distribution, no twin, a malformed or
contradicting stated distribution, the values or events budget) is recorded, and the
same inputs return it. One they
do not decide (the time budget, memory, a broken invariant, a fault, an engine that
will not import) is returned and never recorded.

### 25.7 The service

`simulation_service.simulate_scenario(scenario, *, seed, draws=100_000,
severe_percentile=95)` loads the scenario version as the scenario engine reads it: its
events in key order, each component recomputed from the rows it cites; the policy of
the parameter-set version its build names; each cited row's stated distribution; each
derived row's contributors (`derived_from`) and theirs; and its frequency, the
parameter-set version's or its own (section 25.5). Every
parameter is drawn once per simulated year: the service names none per occurrence. It looks up the result of the same identity, runs the pure engine if
there is none, and records the result. It returns a `SimulationOutcome` (the result,
whether this call recorded it, and the code and detail of a refusal), and **never
raises**: every failure comes back with its code (`engine_unavailable`,
`time_over_budget`, `memory_exhausted`, `invariant_broken`, `simulation_failed`, or the
engine's). It imports the engine, and numpy, only when called, and nothing Django
loads at start imports it (section 23.10).

### 25.8 Limits and timing

Step 7a's limits hold: 1,000 to 1,000,000 draws (`draws_out_of_range`), at most
10,000,000 occurrences across a compound run's years (`events_over_limit`), and at most
30,000,000 values held at once (`values_over_budget`), counted before anything is
sampled (in a compound run, once the years' counts are drawn and before any parameter
is) by `values_held`, stage by stage: drawing and evaluating (each drawn parameter
until its last reader is evaluated, when its draws are let go, the components so far,
and 7a's three temporaries), insurance (the components, the lines, the drawn policy
terms and four temporaries) and the summaries (the components, the lines and two). A
scenario of one event holds its event's lines as the scenario's, never copies. A run is
bounded in time by `TIME_BUDGET_SECONDS` (120), checked between its stages through a
callable the service passes, so the pure engine reads no clock.

Measured on the build machine (4 cores, numpy 2.3.3), each run sampled twice as step
7a does, on the largest template (cross-customer data exposure: seven components, 17
drawn parameters, 11 of them stated and 6 expert PERTs, a policy with a sublimit and
an exclusion): **100,000 draws in 0.32 s** (median of three; 15 MB traced peak);
1,000,000 draws in 3.6 s (145 MB, inside its counted 168 MB); 100,000 simulated years
of a Poisson(3) frequency (about 300,000 occurrences) in 0.65 s (44 MB). The test of
a default run allows 60 s, so it catches a per-draw Python loop and never CI load.

### 25.9 What is still not done

- **Step 8 is done** (section 26): the sensitivity analysis and the most sensitive
  variables, the confidence grade (a material expert figure, fixed or ranged, now lowers it, section 26.2),
  the Validity Card (the owner's specification, section 8) and the signed receipt
  (the Financial Exposure Receipt). What step 8 leaves is section 26.9.
- **Served by step 6** (section 27): its simulate route calls the service.
- **Nothing names a parameter per occurrence.** Since step 6 the parameter set states
  a variable's distribution and the frequency, and the builder an effect attribute's
  (section 19.4), and a version's and a build's digests cover them; nothing yet takes
  `variation: per_occurrence`, so every parameter is drawn once per simulated year.
- **No dependency between parameters** beyond the sharing of section 25.2: no copula,
  no shared-cause event, no correlation between events.
- **One frequency per scenario**, not one per event; every occurrence realises every
  event.
- **The limit is read per event** (section 25.4), with no yearly aggregate cap.
- **One currency per run**: the build's; nothing converts inside it, and currency
  uncertainty stays separate (section 3, rule 6).

### 25.10 Decisions this step takes, which the owner may change

1. The parameter-to-distribution rule of section 25.1: a stated distribution, else a
   point mass, else PERT (weight 4) for an `EXPERT_ESTIMATE` range only, else refused.
   Every other range (a customer's, a benchmark's, an observed or calculated one) must
   state its distribution before it is simulated.
2. **Every parameter is drawn once per simulated year** (review round 1, the lead's
   call, reversing this step's first draft): an effect's attributes too, since a range
   is uncertainty about the figure; per-occurrence drawing is an explicit option per
   parameter (`variation: per_occurrence`), in the input digest, that nothing sets yet.
   Trade-off: once a year can overstate the tail where a range is genuine variation
   between occurrences; per occurrence understated the annual P95 by 27% in the
   reviewer's probe (section 25.2). Alternative: the first draft's split (the set's
   variables, the terms and the frequency once a year, an effect's attributes per
   occurrence).
3. A scenario's frequency is one parameter named `frequency`, and each occurrence
   realises every event of the scenario once.
4. Insurance is applied per event occurrence, as step 4 applies it, the limit
   included; the share of draws whose recoveries exceed the limit is reported.
5. The twins' tolerance is 1E-13 relative, against the Decimal formula at the binary64
   inputs, for normal binary64 results (subnormals excepted, section 25.3). A
   component with no uncertain input is computed by its Decimal formula, an event with
   none (its policy's terms included) by step 4's `assess`, a scenario of such events
   by their Decimal sums, and their summaries are those Decimal values, every digit
   (review round 1). Alternative: summarise the binary64 vector, as the first draft
   did, and state that a constant run is exact only to binary64 (300.29999999999995
   for 300.30).
6. A refusal the inputs decide is recorded; one they do not decide is not.
7. The run's time budget is 120 s, checked between stages.
8. Every version, numpy's included, and every limit that decides a recorded refusal
   (review round 1) are part of the canonical inputs, so a version or limit change is a
   new stored result, never an old one returned. Alternative: leave the limits out and
   never record a budget refusal, returning it each time instead.
9. **A stated distribution must hold its row's figures, from both sides** (review round
   1; closed in step 6). Closed in step 6, before any writer stated a distribution, as
   the lead decided it (the owner may change it). A continuous distribution: the base
   between its P5 and P95 and the low and the high inside the closure of its support, as
   before; its median between the low and the high; and at least `RANGE_MASS_FLOOR`,
   0.5, of its mass between them, both included; and never on a fixed row (low = base =
   high: `distribution_on_fixed_row`, the row is a point mass). A count stated on any
   row but the frequency is held so too: its figures are the count itself (review
   round 1, MEDIUM-1, the lead's call; an observed repeat count stating ZIP(0.5, 6) on
   3 / 3 / 3 is refused). The frequency is held to the rate its count implies instead
   (decision 12). Refused otherwise (`distribution_contradicts_range`, naming the
   parameter and the test it failed, each compared figure in full), at write, build and
   run time, by one function (a build re-checks its set version's distributions under
   the rule then in force: review round 1, LOW-3). Alternative for observed counts,
   not taken: refuse any stated distribution on a `MYTHOS_OBSERVED` attribute (the
   observation is the figure); the fixed-row refusal already refuses one on a fixed
   observed figure, and an observed range may state one that holds it. The
   thresholds are the owner's: P5 and P95, the closed support (so a low of 0 fits a
   lognormal or a gamma), and the floor of 0.5. With the floor at 0.5, a median outside
   the range leaves at most half the mass inside it, so the mass test alone refuses
   nearly every case the median test does; the median test is kept, and named, so a
   refusal says which side failed, and so a lower floor keeps a two-sided test. The floor
   and the percentiles are limits of the inputs (`limits`), so changing either is a new
   input digest, and the rule is v3. Alternatives for the floor: 0.8 (the row's low and
   high as roughly its P10 and P90), 0.9 (as its P5 and P95), or a lower one with the
   median test alone carrying the two-sided check; for the test: a narrower one (the
   base between P10 and P90, or each of low, base and high near its own percentile), a
   wider one (the base anywhere in the support), or a warning recorded with the run
   instead of a refusal.
10. **A derived parameter draws from its contributors** (review round 1): each by its
    own rule, per draw the larger loss in the inputs' direction, refused where any
    contributor is, naming it (section 25.1, rule 5). Alternatives: refuse every
    derived range (the first draft: safe, but a dead end, since no writer can state a
    distribution and rows are append-only), or a PERT of the merged range (not sound:
    a PERT of pointwise maxima need not bound the expected maximum).
11. **The transaction only inserts** (review round 1, as section 24's decision 11): a
    result's checks, its lookup of the same identity included, run before it, so a run
    that lands between the check and the INSERT is stopped by the unique constraint and
    the first's row is returned. Alternative: the save's own checks inside the
    transaction, as first drafted, which a test on one connection cannot race (the
    other row would be rolled back with the savepoint).
12. **A frequency's figures are its rate, not its count, and the rate its count implies
    is held to them; one frequency per parameter-set version** (step 6, the lead's call;
    review round 1, MEDIUM-1 and MEDIUM-2, the lead's calls; section 25.1). A frequency
    row's low, base and high are values of its annual RATE, which step 4's formulas
    multiply into annual loss; a stated count distribution says how the count varies
    from year to year given the rate, and how uncertain the rate is. The first draft of
    step 6 held a count to its median and its mass in range, which compares the count's
    yearly spread with the rate's uncertainty: it refused Poisson(5) on 4 / 5 / 6 (49.7%
    of its count in range), refused 0.01 / 0.05 / 0.2 (no whole number in range), and
    left no way to write a rate known exactly. The second held a count by its mean
    alone, which let an over-dispersed count state a rate that contradicts the row (a
    negative binomial of mean 1,200 and size 0.1 on 1,000 / 1,200 / 1,400: its rate's
    median 7 a year) and reached every count row, an observed repeat count's included.
    Now the reading is the FREQUENCY's alone: every other count row holds the count
    itself and is held from both sides (decision 9). The frequency is held by its mean
    between the low and the high, exactly from its stated parameters (`rate`); its
    support; round 2's base rule, kept because it refuses a base far from the mean while
    the mean is in range (0 / 1 / 2 with Poisson(0.02)); and the rate its count implies
    from both sides (`rate_median`, `rate_mass`, the floor of decision 9): a Poisson's
    rate is its lambda, a negative binomial's is Gamma(size, (1 - p) / p), a
    zero-inflated Poisson's is 0 with probability pi and lambda otherwise. A fixed rate
    (2 / 2 / 2) is a known rate, and may state only a count whose implied rate is that
    point, a Poisson of the figure; a negative binomial, or a zero-inflated Poisson with
    pi above 0, states the rate uncertain and is refused (`distribution_on_fixed_row`).
    The frequency is stated in the set's document, applies to every scenario built from
    that version, and is read through the build, as the policy's terms are; a
    scenario's own `frequency` row beside it is refused. Alternatives: for the rate, the
    mean alone (the second draft: an over-dispersed count passes whatever its rate's
    spread), or a narrower band for the implied rate (its P10 and P90 inside the range);
    for the base rule, dropped, or a count's mean within a tolerance of its base; for
    the frequency, one per scenario, in the build's request, or one per template in the
    set (one per set version stays for the MVP).

## 26. Sensitivity, grade, Validity Card and receipt (MVP step 8)

MVP step 8, on step 7b's stored result (section 25.6): which parameters drive the
result's uncertainty (the owner's specification, section 20's tornado), the
confidence grade with its reason (section 8's table, and spec-v1's downgrades), the
Financial Exposure Validity Card (section 8's fields; section 15's
`FinancialValidityCard`) and the signed Financial Exposure Receipt (section 15's
`FinancialExposureReceipt`; section 28's receipt tampering), built with
`mythos_core.exposure_receipt`, which E1 pinned and nothing called before. No route
is added here: step 6 (section 27) serves the scenario endpoints and the report, and
calls these services.

| | |
|---|---|
| Code | `assurance/economics/engine/sensitivity.py` and `engine/grade.py` (pure; the analysis imports numpy, the grade does not); `assurance/economics/validity_service.py` (the card) and `receipt_service.py` (the receipt), thin Django services; `FinancialValidityCard` and `FinancialExposureReceipt` in `models.py`; `CyberEngineClient.sign_exposure_receipt` |
| Migration | `0065_financial_validity_cards_and_receipts.py`: two new tables, nothing else changed; the follow-up's `0066_scenario_fingerprint_unavailable.py`: one column on `FinancialScenario` (section 24.6) |
| Tests | `tests/test_economics_sensitivity_and_grade.py` (no database) and `tests/test_economics_validity_card.py`; the safety tests of sections 2 and 23.10 extended to the four new modules and `mythos_core.exposure_receipt`; `tests/test_firing_twice_makes_one_effect.py` (the engine's signing call) |
| mythos-core | `b1f6e9d`: `mythos_core.exposure_receipt`, `mythos.financial-exposure-receipt/v1` (Mythos-Core#49) |

### 26.1 Sensitivity

`engine/sensitivity.py`, method `mythos.economics.sensitivity` version 2
(`sensitivity.version_record()`, in every record; version 1 was #153's, which split a
sum inside a formula by elasticity: decision 8). Made on the run's OWN draws:
`sensitivity.analyse` reloads the scenario version as step 7b read it, and refuses
unless its canonical inputs give the run's input digest (`inputs_changed`) and its
draws, made again from the same seed and sub-streams, give the run's outcomes
digest (`result_not_reproduced`: another numpy or platform, section 23.8). Each
parameter's draws are made again from its own stream (section 25.2), so they are the
very draws the run evaluated.

- **The output** is the scenario's gross cash loss: per simulated year where the
  run has a frequency (basis `annual_loss`), per occurrence otherwise
  (`per_occurrence`). Insurance and market value are not in it.
- **The ranking: contribution to variance by rank correlation.** For every
  uncertain parameter a known cash component reads (and the frequency, in an annual
  run), the Spearman rank correlation of its draws (its yearly draws, in an annual
  run) with the output, ties at their mean rank. Its **importance** is its squared
  correlation over the sum of every ranked parameter's, so the importances sum to
  one; its **direction** is the correlation's sign (`increases`, `decreases`, or
  `none` for exactly zero). The sums are taken over whole numbers -- twice each
  centred rank, at most 2 x 10^6 in size over at most 10^6 draws, so no partial sum
  leaves int64 -- so the correlation is exact for the draws and the same on every
  platform; importance and correlation are written to 10 decimal places. For a sum
  of independent parameters the importances are close to their shares of the
  variance (Spearman's correlation is the rank form of Pearson's, whose square is
  the share exactly); for a skewed or non-additive formula they rank by monotone
  association, which is what a tornado is read for.
- **The tornado: one at a time.** Every other uncertain parameter at its P50, the
  one swung to its P10 and then its P90 (type 7 quantiles of its own draws, as the
  run's summaries), and the gross cash evaluated by the formula twins (section 25.3)
  per occurrence; in an annual run, times the frequency's mean count over the run's
  years (every parameter is shared by a year's occurrences, section 25.2, so a year
  at fixed parameters is N occurrences of one). The frequency's own swing is its P10
  and P90 count. Each swing records the P10, P50 and P90 and the low and high
  outcome, as decimal strings.
- **Not ranked, and listed with the reason:** a point mass is `fixed` (it draws
  nothing, and its value is recorded); a parameter only the policy or a market-value
  line reads is `not_in_gross_cash`; a parameter drawn per occurrence (nothing names
  one yet, section 25.9) has no one value a year.
- **Bounded.** Every ranked parameter's importance is recorded: the run already
  holds one vector of draws per parameter within 7a's values budget (section 23.9),
  so their number is bounded by it, and the analysis holds one parameter's draws at
  a time beside the run's own vectors. At most `MAX_SWINGS` (20) parameters are
  swung, the most important first; the card names the top `TOP_DRIVERS` (5).

- **The level** (review round 1, H1; review round 2, HIGH 1 and MEDIUM 2): each
  figure's share of the result's LEVEL, which the grade weighs by (section 26.2), as
  **an ADDITIVE decomposition at base** -- every parameter at its base, FIXED OR
  RANGED alike, so the shares depend on the bases only:
  - **The gross cash** is the sum of its known cash components. Each component
    carries exactly its base over the total (step 4's Decimal figure at base), split
    among its OWN inputs:
    - **by its additive terms first, where its formula is a sum** (step 8's
      follow-up; `Formula.terms`: `fixed_plus_hours` is `fixed_cost` + `hourly_rate`
      x `hours`, `per_affected_plus_fixed` is `affected` x `unit_cost` +
      `fixed_cost`, and every other formula of the catalogue is one term). Each term
      carries its base over the component's, exactly, from the bases only -- a term's
      base is the product of its factors' bases, a recovery's through 1 - r -- and
      then each term is split among its own factors: each factor of a product has
      elasticity one in it, so a product of k factors gives each 1/k of the term. A
      factor of two terms gets the sum of its parts. So a fixed amount F beside a
      product P carries exactly F / (F + P) of the component, as it would as a
      component of its own; #153 split the whole sum by elasticity, which gave it
      F / (F + 2P) beside a two-factor product (decision 8). The piece lists its
      `terms`, each with its inputs, `base` and `weight` in the component;
    - **in proportion to their elasticity of the component at base, where its
      formula is one term** (by its formula twin, a central difference of
      `LEVEL_STEP`, 0.1%, either side), exactly as #153 did. Each factor of a product
      has elasticity one, so a product of k factors gives each 1/k of it; an input
      that lowers the loss (a recovery rate r, read as 1 - r) is moved through that
      complement, one factor like any other -- never r / (1 - r), which let a
      customer recovery of 0.99 swamp an expert lump three times its product (the
      round-2 finding). A cap (`capped_credit`) goes to the cap where it binds, to the
      product where it does not, a third each at the kink.

    An input read twice adds both. Every formula of the catalogue declares its terms,
    and each declaration is proven against the formula itself: a sum is exactly the
    sum of its terms' products at random points, and zeroing one factor removes
    exactly its term; one term is not a sum, since zeroing any one of its factors
    zeroes the whole (`test_every_formula_declares_its_additive_terms_and_they_are_its_own`).
  - **The frequency.** With a frequency the headline is frequency x severity: the
    frequency carries one half, and the severity's decomposition the other, however
    many factors the severity's formulas have.
  - **The retained cash**, where a policy applies, is decomposed the same way, per
    event as the insurance applies (section 25.4), into additive pieces that sum
    exactly to step 4's retained cash at base: the cash the policy leaves uncovered (an
    excluded or never-covered family, business interruption without a stated waiting
    period), the business interruption a waiting period above zero leaves uncovered
    (one half the waiting period's, one half the interruption's own inputs), each
    covered family's excess over its sublimit (split amount : sublimit, their
    elasticities at base), what the deductible keeps (the deductible where the covered
    cash passes it, the covered cash where it does not, half each at the kink) and
    what passes the limit (split covered : deductible : limit). The covered cash's part
    splits down to its families, their components and their inputs by base.
  - A line's shares sum to exactly one (checked as fractions before they are written
    to 10 places; `invariant_broken` otherwise). A line that is zero at base, or a
    frequency whose base is zero (a base-case year holds no occurrence; review round
    2, LOW 3), has no level: `defined: false`, and why.
  A derived value names its contributors and those whose base supplies its own
  (`supplied_by`).

The record (schema `mythos.economics.sensitivity/v1`) holds the method, the seed,
draws, input and outcomes digests, the basis, the currency, every ranked parameter
(`name`, `rank`, `importance`, `rank_correlation`, `direction`, `source_types` --
its own, or a derived parameter's contributors' --, `rule`, `expert`,
`derived_from`, `frequency`, `swing`), the swing baseline, the unranked lists and
the level: `gross_cash` and `retained_cash` (null without a policy), each with its
`basis`, `base`, `frequency_base`, `defined` and `undefined_because`, its `pieces`
(each a component or a retained piece -- `uncovered`, `uncovered_by_waiting_period`,
`sublimit_excess`, `deductible`, `beyond_limit` -- with its `base`, `share` and
`split`, a component's `inputs` with each input's `elasticity`, `complement` and
`weight` (its part of the component), and, for a formula that is a sum, its `terms`
with each one's `inputs`, `base` and `weight`), and for every figure the line reads
its `base`, `source_type`, `share`,
`fixed`, `frequency`, `policy_term`, `derived_from` and `supplied_by`.
Nothing in it is a float; its digest is the canonical JSON's SHA-256, and the card
names it.

Known answers (`tests/test_economics_sensitivity_and_grade.py`): one wide expert
range beside a narrow one ranks first with importance above 0.999 and direction
`increases`; X1 + X2, independent symmetric PERTs whose widths are 2:1 (variances
4:1), give 0.8 and 0.2 within 0.03 at 100,000 draws (measured 0.815 and 0.185), and
equal variances one half each; a recovery rate reads `decreases`, and its P90 swing
gives the lower outcome; the same seed gives the same record, another seed another;
the frequency of an annual run ranks first where the severity is narrow. The level:
4M-6M (an expert range), a fixed 1M and a customer gamma of base 100,000 share it
5 : 1 : 0.1 to 1E-9; the three factors of `repeat_loss` a third each at a recovery of
0.5, 0.9 and 0.99; one expert factor of a product of k (2 to 5) carries 1/k of it; a
frequency exactly one half, beside a four-factor product too; a frequency whose base
is zero has no level. The reviewer's round-2 cases, each graded A before: (a) an
expert lump of 3M beside a customer `repeat_loss` of 100 x 1M x (1 - 0.99) carries
0.75 and grades D (likewise 85% and 95%: never A); (b) 19M beside 1000 x 1M x
(1 - 0.999), 0.95, D; (c) 200,000 beside a customer `support_contacts` of 1M, 1/6,
C; (d) an expert frequency beside a customer recovery of 0.95, one half, D; (e) an
expert count range inside a customer product, a third at every recovery, D at 0.5,
0.9 and 0.99 alike. Under a policy: an expert deductible that IS the retained cash
carries the retained line's severity half (retained D, gross A, headline D); an
expert limit of 950,000 under 1M, 0.5 x 95/195 (retained C); the retained pieces sum
to step 4's Decimal retained cash to the last digit, with a sublimit (and at its
kink), an exclusion, a waiting period above zero and at zero, and a deductible above
the covered cash. Additive terms (step 8's follow-up): a fixed amount equal to the
product beside it carries one half of its component in `fixed_plus_hours` and in
`per_affected_plus_fixed` (one third by #153's elasticity), each factor of the
product a quarter; an expert fixed amount of 75% of its component, the component 8%
of the level, carries 0.06 and grades C, where #153 gave it 0.048 and A; a factor of
two terms gets the sum of its parts (a + a x b at 2 and 3: 5/8); and every cash
formula of one term gives the level record #153's head (b89624f) gave, both lines,
byte for byte (its SHA-256, pinned per formula, with a frequency and a policy whose
limit the gross passes, and `capped_credit` bound, unbound and at its kink).

Measured on the build machine (4 cores, numpy 2.3.3), on the largest template
(section 25.8's: 16 ranked parameters): 100,000 draws in 0.25 s (median of three;
15 MB traced peak); 1,000,000 draws in 3.2 s (145 MB); 100,000 simulated years of a
Poisson(3) frequency in 0.44 s. The analysis samples once (the run sampled twice).

### 26.2 The confidence grade

`engine/grade.py`, `mythos.economics.confidence-grade/v2`. A grade is computed from
a line's **evidence mix**: the share of the line's LEVEL that rests on each class of
source, each figure the line reads -- and the frequency -- weighted by its share of
the base-case level (section 26.1's additive decomposition),
**never by a raw count**, and **a fixed
figure exactly as a range at the same base** (review round 1, H1): an expert's
$5,000,000 guess is the evidence it is whether it is stated as one figure or as a
range around it. A derived value (the builder's larger loss, section 24.5) rests on
the contributors whose base supplies its own: its share is split equally among their
source types. The variance importance (section 26.1) ranks the most sensitive
variables on the card and weighs nothing in the grade.

**Two lines, and the headline grade is the lower of the two** (review round 2,
MEDIUM 2; `grade.headline`, `grade.HEADLINE_RULE`, in the grade's version record).
Without a policy the gross cash is graded, and that is the card's grade. Under a
policy the headline figures -- the card's and the receipt's -- are the retained
cash, so both lines are graded, each by its own level with the same thresholds and
downgrades: the gross cash, and the retained cash, whose level reads the policy's
terms too (deductible, limit, sublimits, waiting period). The card's grade is the
LOWER of the two (`Unknown` lowest); equal, the retained cash's. The card shows both
(`confidence_grade.lines`), which line the headline is (`line`), and the evidence-mix
fields of that line. An expert's deductible that is the retained cash, which the
gross never reads, lowers the card's grade.

| Source type | Class | Counts as |
|---|---|---|
| `CUSTOMER_PROVIDED` | `customer` | evidence |
| `MYTHOS_OBSERVED` | `observed` | evidence |
| `OFFICIAL_PUBLIC`, `LICENSED_MARKET` | `authoritative` | evidence |
| `CALCULATED` | `calculated` | neither |
| `INDUSTRY_BENCHMARK` | `benchmark` | neither |
| `EXPERT_ESTIMATE` | `expert` | assumption |
| `UNKNOWN` | `unsourced` | assumption |

The thresholds (`grade.THRESHOLDS`, the owner's to set), compared exactly as
fractions; the first that holds is the base grade:

| Grade | Evidence share at least | Assumption share at most | The owner's typical mix (section 8) |
|---|---|---|---|
| A | 0.80 | 0.05 | mostly customer-specific + observed + authoritative |
| B | 0.50 | 0.25 | customer + Mythos evidence + moderate benchmarks |
| C | -- | 0.50 | benchmark-heavy |
| D | otherwise | | mostly assumptions / weak priors |

Then spec-v1's downgrades (section 12.5's rule: one step each, A to B to C to D,
never below D), **each firing at most once**. A figure is MATERIAL where its level
share is at least `MATERIAL_SHARE` (0.05):

| Downgrade | Fires when |
|---|---|
| `stale_inputs` | a figure the run reads -- a known cash component's, a term of the policy the run applies, the frequency, or a contributor of a derived value the gross reads -- is past its `fresh_until` at the run's as-of date (section 26.3) |
| `expert_figures` | a material figure rests on an expert's estimate or on no named source (`EXPERT_ESTIMATE`, `UNKNOWN`; a derived value, on a supplying contributor's), fixed or ranged |
| `derived_values` | a material figure is a derived larger-loss value |

**Collapsing a range to one figure at its base never raises the grade**: the level
shares, the source types and the dates are those of the base, which a collapse keeps,
and nothing in the grade reads a range's width
(`test_collapsing_a_range_to_its_base_never_raises_the_grade`: the reviewer's three
cases -- a 4M-6M expert fine beside a customer gamma, the same with a frequency, and
twenty customer figures of $1 beside an expert $5,000,000, which grades D and never
A -- a product of expert ranges, and a wide expert range carrying the variance but
3% of the level; and, under a policy, an expert's deductible and limit as ranges,
graded by the headline; each range alone and all together). This is why materiality reads
the level only (section 26.10, decision 6): a downgrade a range's variance fired
would be removed by collapsing it.

`Unknown` -- Mythos cannot responsibly quantify the scenario -- where the run was
refused (its reason says "the inputs conflict" for `distribution_contradicts_range`,
`derived_malformed`, `currency_mismatch`, `duplicate_id` and
`spine_effect_inconsistent`); where a cash component is unknown (the cash figure
would read only "at least"; the evidence mix is still shown); where the line has no
level to weigh (there is no fallback to counting): the base-case gross is zero, the
frequency's base is zero (review round 2, LOW 3), or under a policy the base-case
retained cash is zero, which makes the headline Unknown; and where an
annual run draws a parameter per occurrence (review round 1, L6: such a parameter is
neither ranked nor weighed yet; nothing names one today, section 25.9). A range the
distribution rule refuses (section 25.1) leaves the run refused, and so Unknown,
where its point would be graded: Unknown is not a rung of the ladder.

Every grade carries its reason in words (the shares, the base grade and each
downgrade with the figures that fired it) and `version_digest`: the SHA-256 of
`grade.version_record()` -- the weighting, the two-line rule, the classes, the
thresholds, the materiality, the downgrades and the conflict codes -- so a changed threshold is a new
digest on every card, and in the release the card records (section 26.5).

### 26.3 The Validity Card

`validity_service.build_card`, schema `mythos.economics.validity-card/v1`. A JSON
document with every field of the owner's table (section 8), under `fields`, in the
table's order. Each comes from the stored result, the scenario version's
append-only rows or the stored sensitivity analysis, or from `issued` (what was read
when the card was issued, kept as issued); where a field has no data, it says so.
No value is made up.

| Owner field | Card key | Source |
|---|---|---|
| Scenario ID / description | `scenario` | the scenario version's uuid and title; each loss event's trigger, business process, SPINE effect and template (`LossEvent`, `CausalEffect`); a plain-English description made from them ("Cross-customer exposure. 1 causal loss event(s): cross_customer_disclosure on customer_service, priced by cross_customer_data_exposure v1, enabled by 1 finding(s).") |
| Model version | `model_version` | the release token and build digest (section 26.5) and the RELEASE RECORD they are taken over (`release`: the run's `versions`, every version and limit, section 25.6; the sensitivity method; the grade's version record; the card's schema), which verification reads (section 26.6); the inventory entry an admin registered for `economic-exposure` at that token (`issued`), or "no model inventory entry registers ..." |
| System fingerprint | `system_fingerprint` | the scenario version's own `system_fingerprint` where it was recorded (`binding: scenario`) -- the builder records the deployment's when it builds the version (section 24.6), so a card binds the BUILD's state, and the deployment's then is not read (`issued.deployment_system_fingerprint` is null) and appears nowhere on the card, however the deployment has changed since; otherwise the deployment's SPINE fingerprint (`assurance.fingerprint.compute_system_fingerprint`) read when the card was issued (`binding: deployment_at_issue`, and the statement says it is not the build's, and, where the builder recorded why it had none, that reason); otherwise `value: null` and "unavailable", with the reasons. A version recorded before the builder recorded fingerprints reads exactly as before (`test_an_older_version_with_no_fingerprint_keeps_the_fallback_unchanged`) |
| Technical evidence | `technical_evidence` | each observed effect (its SPINE row's uuid, observation digest, SPINE effect, time; status: in force when the scenario was built, which the builder requires), each hypothetical effect, and each enabling finding with its role and its status and severity when the card was issued (`issued`) |
| Customer-specific share | `customer_specific_share` | the evidence mix's `customer` share of the line the headline grade is (`line`), its weighting (`level`), and every customer figure that line reads with its level share and, beside it, its importance |
| Benchmark-derived share | `benchmark_derived_share` | the `benchmark` share, likewise |
| Expert-estimated share | `expert_estimated_share` | the `expert` and `unsourced` shares, likewise |
| Confidence grade | `confidence_grade` | section 26.2's headline grade, base grade, reason, evidence mix, downgrades and version digest; the line it is (`line`) and the rule (`rule`); and each line's own grade (`lines`: `gross_cash`, and `retained_cash` under a policy, else null) |
| Last calibrated | `last_calibrated` | `{"date": null, "calibration_set": null, "statement": "never; no calibration set exists"}` |
| Most sensitive variables | `most_sensitive_variables` | the analysis's top five: name, rank, importance, direction, source types, swing outcomes; the fixed parameters; or "unavailable" for a refused run |
| Data freshness | `data_freshness` | EVERY figure, each evaluated at the run's as-of date (its build's, else its components'): every parameter of the run's inputs -- the components', the policy's terms, the frequency, every derived value's contributors --, every parameter of the scenario version nothing reads (the receipt binds them among its `scenario-parameters`; review round 2, LOW 4) and every variable of the parameter-set version no component reads, each read by "nothing" and said where it is; for each its source type, what reads it (`read_by`), effective date, `fresh_until`, whether it was evaluated, its age in days, stale or not, whether it counts toward the grade, critical or not (a top driver or material); the stale ones that count (`stale`) and those shown only (`stale_not_graded`). With no as-of date, every figure says it was not evaluated (`stale: null`), never fresh (review round 1, M3) |
| P10/P50/P90/mean | `figures` | the headline line's (retained cash under a policy, else gross cash) P10, P50, P90, mean, expected annual exposure and severe-but-plausible, and the gross cash's, at full precision as stored; a null figure does not exist for the run (no frequency: no expected annual exposure) and is never estimated; "unavailable" for a refused run |
| Unknown variables | `unknown_variables` | every unknown component with its reason and missing inputs, and a refused run's refusal |
| Reproduction seed/hash | `reproduction` | the seed, draws, severe percentile, input digest, result digest, outcomes digest and the analysis's digest, and how to replay |

Beside `fields`, the card carries section 15's `FinancialValidityCard` key fields:
`scenario_id`, `evidence_mix`, `assumptions` (the expert ranges and the rules a run
rests on), `unknowns`, `freshness`, `calibration_date` (null), `reviewer_status` (the
scenario's review status when issued); and `confidence_grade` at its top, which
`mythos_core.exposure_receipt` reads.

**Reproducible from what is stored.** `build_card` given the stored result, the
stored analysis and the card's own `issued` section gives the stored card, digest
for digest (`validity_service.reproduces`). The analysis itself, made again from
the stored result, is the stored one.

### 26.4 The stored card

`FinancialValidityCard`, append-only like every economics record, with no account
column, going with its deployment: the deployment, the scenario, the simulation
result (ONE-TO-ONE: one card per result), the schema, the grade and the grade's
version digest, the card and its digest (`models.card_digest`, which is
`exposure_receipt.card_digest_of` computed without importing it), the sensitivity
analysis and its digest (both null for a refused run: `ck_econ_card_sensitivity_digest`),
when it was issued. The grade is a check constraint (`ck_econ_card_grade`). Every
check -- the tenant, the card's scenario and grade, no float, both digests, a card
of the same result -- runs before the transaction, which only inserts; two issues
racing past the lookup are stopped by the one-to-one key, and the later returns the
first's card.

`validity_service.issue_card(result)` returns the card recorded, or makes and
records one: it **never raises**. A failure the stored rows do not decide
(`engine_unavailable`, `inputs_changed`, `result_not_reproduced`, `time_over_budget`
(the run's 120 s budget, checked between stages), `memory_exhausted`,
`invariant_broken`, `card_failed`) is returned and never recorded, so a later issue
is not refused by an accident.

### 26.5 The receipt

`receipt_service.issue_receipt(result)` builds the document with
`exposure_receipt.build_receipt` (`mythos.financial-exposure-receipt/v1`) from the
stored rows:

| Receipt field | From |
|---|---|
| `scenario_id`, `tenant_id` | the scenario version's uuid; the deployment's uuid (a Deployment is the tenant boundary) |
| `system_fingerprint` | the card's `system_fingerprint.value` |
| `model.version`, `model.build_digest` | the release the CARD records (`validity_service.model_release` when it was issued): the token `mythos.economics:simulation-<engine>+sensitivity-<n>+card-<n>`, and the SHA-256 of its release record -- the run's versions and limits, the sensitivity method, the grade's version record and the card's schema |
| `simulation.seed`, `simulation.draws` | the result's |
| `simulation.parameter_set_digest` | the result's input digest: every parameter the run read, with its figures, source, stated distribution and variation, and every version |
| `sources` | each source snapshot the run read, its content hash recomputed from its stored rows (`source_snapshot_mismatch` where a recorded digest no longer reproduces): `parameter-set:<key>:<version>` (its content digest, `intact()`), `scenario-build:<scenario>` (its build digest, recomputed from its inputs) and `scenario-parameters:<scenario>` (the SHA-256 of every parameter row of the scenario version) |
| `evidence` | `nodes`: the effects' assets; `effects`: their SPINE effects; `claims`: none (no claim is linked to a scenario yet) |
| `result` | the reporting currency, the valuation date (the build's as-of date), and the headline line's six figures rounded half-even to the currency's minor unit (`Money.display_amount`) |
| `validity_card` | the card's digest and grade, read by core from the card itself |

It is **signed on the path the backend's signed assurance receipts take**: the
backend holds no signing key and asks the engine
(`CyberEngineClient.sign_exposure_receipt`, `POST /api/economics/exposure-receipt/sign`,
the operator credential, as `sign_assurance_receipt`). The envelope that comes back
must be one signature over exactly the document's canonical bytes under the
receipt's payload type (`envelope_not_over_receipt` otherwise), and it must VERIFY
with core's verifier against the caller's `ReceiptKeyring` before anything is
recorded (core's code otherwise): **no signature nobody has checked is ever recorded**
(review round 1, M2). The keyring is required: it is built from the keyring the
engine publishes at `GET /api/assurance/keyring` (athena-engine #88,
`receipt_service.keyring_from_published`, or `engine_keyring` to fetch it): its
`keys` are the artifact role's (evidence packs and assurance receipts) and its
`roles` hold each other signing role's keyring in the same form (`keys` by key id,
each a base64 `public_key` and a `status`), `economics-receipt` among them. That
role's active and retired keys are the receipt keys; the artifact keys and every
other role's are filed under their roles, so a receipt one of them signed is refused
as `wrong_role`; a revoked key verifies nothing; a published keyring without the
role is no keyring. Without one, `issue_receipt` records nothing and returns nothing
(`keyring_unavailable`). A recorded receipt is returned only where it verifies
against the keyring; one that does not is never returned as the result's receipt and
never overwritten (`recorded_receipt_unverified`, with the verification's code). A
signer can be handed in; the tests sign with `Ed25519PrivateKey.generate()` keys, as
the existing receipt tests do.

The engine validates the document with core before it signs (athena-engine #88). A
document core refuses is a 400 whose `detail` is `{"code": <core's code>, "reason":
...}`: the client raises it as `ExposureReceiptRefused`, and the service returns
`receipt_refused_by_signer` with core's code (`ReceiptOutcome.signer_code`) and
records nothing -- the document was refused, not the signer unavailable. Only a code
of core's own (`exposure_receipt.MALFORMED_CODES`) is carried as core's: a 400 with
any other code (`rate_limited`, `signer_not_configured` at 400) is still
`receipt_refused_by_signer`, the code shown in the detail and `signer_code` null
(review round 2, LOW 6). A 503 (a
role not configured: `signer_not_configured`), a connection failure, a timeout, a
400 that names no code, or an engine without the route is `signer_unavailable`
(`test_a_document_the_engine_refuses_is_refused_by_the_signer_not_unavailable`).

`FinancialExposureReceipt` is append-only, with no account column, going with its
deployment: the deployment, the scenario, the result and the card (one-to-one each:
**the same result gives the same receipt row**), the receipt id, the document, the
envelope, the key id and when it was generated. On save its document must be core's
schema and name the row's own scenario, tenant, id and card digest, and the envelope
be one signature over exactly its canonical bytes, in core's signature form -- the
88-character base64 of a 64-byte signature -- with the row's key id
(`receipt_record_malformed`).

A receipt that cannot be built or signed is returned with its code and **never
recorded**: `result_not_completed`, `receipt_figure_unavailable` (a run without a
frequency has no expected annual exposure, and core requires all six figures),
`system_fingerprint_unavailable`, `source_snapshot_mismatch`, core's
`bad_integer` (a seed past 2^53 - 1, which core refuses), `signer_unavailable`,
`receipt_refused_by_signer`,
`envelope_not_over_receipt`, core's verdict codes, `keyring_unavailable`,
`recorded_receipt_unverified`, `card_unavailable` (or the card's own failure code),
`receipt_failed`. The service never raises.

### 26.6 Verification

`receipt_service.verify_stored_receipt(receipt, keyring)` never raises. In order, and
the first failure decides:

1. `exposure_receipt.verify_receipt(envelope, keyring, card=<the stored card>)`: the
   envelope's shape, the payload type, the key held and in the `economics-receipt`
   role, the signature, the schema and canonical bytes, and the card -- its digest,
   scenario and grade (core's verdicts and codes: `forged`, `unknown_key`,
   `wrong_role`, `card_digest_mismatch`, ...);
2. the row itself (review round 1, L5): its deployment and scenario are its result's
   and its card's, its result is its card's, and its receipt id, key id and instant
   are the document's, the envelope's and the verifier's (`receipt_row_mismatch`): a
   row moved to another deployment, or relabelled, is refused before step 6 lists one;
3. the stored document is the signed payload (`receipt_mismatch`);
4. the stored result's inputs still give its input digest and its record its result
   digest (`result_digest_mismatch`, whose reason names which was compared; the
   inputs, review round 1, M4), and the card's
   and the receipt's digests, seed, draws and six figures are the stored result's
   (`result_mismatch`);
5. the scenario and tenant (`receipt_mismatch`), the system fingerprint
   (`fingerprint_mismatch`), the model build -- the receipt names the release the
   card records, that release's digest is the build digest, and its run versions are
   the stored result's (`model_build_mismatch`) --, every source snapshot recomputed
   from its rows (`source_snapshot_mismatch`) and the evidence recomputed from the
   effects (`evidence_mismatch`);
6. the card: its stored analysis is the one it signs, under any release -- the
   SHA-256 of the stored sensitivity record is the card's
   `reproduction.sensitivity_digest` (`sensitivity_digest_mismatch`; review round 2,
   LOW 5) --; and where today's release is the one the card records, the stored card is
   rebuilt, digest for digest, from the stored result, analysis and rows
   (`card_not_reproduced`). Where the release has changed since -- a constant of the
   analysis, the grade or the card -- today's code cannot rebuild yesterday's card;
   that is said as the notes `release_changed` and `card_not_rebuilt` beside an
   otherwise authentic verdict (`ReceiptCheck.notes`, and its reason says the card was
   not rebuilt), **never read as tampering** (review round 1, L7). What only a rebuild
   checks -- the loss events' labels, the card's own fields -- is then not checked.

Tested by tampering each past the append-only checks (the base manager, section 10):
the card (`card_digest_mismatch`), the result's record (`result_digest_mismatch`) and
its digest with it (`result_mismatch`), a parameter-set row and a scenario parameter
(`source_snapshot_mismatch`), the signature (`forged`), the document
(`receipt_mismatch`); a stranger's keyring (`unknown_key`), the signing key filed
under another role (`wrong_role`), a plain mapping (`unknown_key`); the result's
inputs (`result_digest_mismatch`); the row's deployment, key id, receipt id and
instant (`receipt_row_mismatch`); the run's versions (`model_build_mismatch`); a
grade constant changed since (verified, with `release_changed` and
`card_not_rebuilt`); and the stored analysis under today's release and a changed one
(`sensitivity_digest_mismatch`).

What a verified receipt establishes is core's: the holder of an
`economics-receipt` key signed exactly this document, and the card presented is the
one it names; and, from this service, that the stored result, card and snapshots
are still the ones signed. Not that the numbers are right.

### 26.7 Codes

The services' own codes (`receipt_service.REFUSALS`, `sensitivity.REFUSALS`, and the
two row codes in `models.CARD_RECORD_REFUSALS`); a code core or step 7b publishes is
returned as theirs, with their meaning, and none is published twice with another:

| Code | Meaning |
|---|---|
| `inputs_changed` | the scenario's stored rows no longer give the run's canonical inputs |
| `result_not_reproduced` | the draws made again are not the run's (another numpy or platform) |
| `card_failed` | an unexpected fault while making a card: nothing recorded |
| `card_record_malformed` | a card row that is not its own result's card: another scenario, another grade, a float, a digest that is not the card's or the analysis's |
| `receipt_record_malformed` | a receipt row whose document is not core's schema, names another scenario, tenant, id or card, or whose envelope is not one signature, in core's form, over exactly it |
| `result_not_completed` | a refused run has no figures to sign |
| `receipt_figure_unavailable` | one of the six figures does not exist for the run |
| `system_fingerprint_unavailable` | the card names no fingerprint to bind |
| `source_snapshot_mismatch` | a source snapshot's rows no longer give its content hash |
| `signer_unavailable` | nothing could sign: the engine was not reached or timed out, has no key in the role (503), or serves no signing route |
| `receipt_refused_by_signer` | the signer read the receipt and refused it: core's code is carried beside (`signer_code`) where it is one of core's `MALFORMED_CODES`; any other code is shown in the detail, never carried as core's |
| `envelope_not_over_receipt` | the signer returned something other than one signature over exactly the receipt |
| `card_unavailable` | no card, and none could be issued |
| `keyring_unavailable` | no `ReceiptKeyring` of the engine's published economics-receipt keys: nothing recorded or returned |
| `recorded_receipt_unverified` | the receipt recorded for the result does not verify: not returned, never overwritten |
| `receipt_row_mismatch` | the stored row's deployment, scenario, result, card, receipt id, key id or instant are not the ones its result, card, document and envelope name |
| `receipt_failed` | an unexpected fault: nothing recorded |
| `receipt_mismatch` | the stored document is not the signed payload, or names another scenario or tenant |
| `result_digest_mismatch` | the stored inputs no longer give the input digest, or the record the result digest; the reason names which was compared |
| `result_mismatch` | a digest, the seed, the draws or a figure is not the stored result's |
| `model_build_mismatch` | the receipt does not name the release the card records, that release's digest is not the build digest, or its run versions are not the stored result's |
| `evidence_mismatch` | the effects no longer give the SPINE evidence signed |
| `fingerprint_mismatch` | the receipt binds another fingerprint than its card names |
| `card_not_reproduced` | under the release the card records, the stored rows no longer rebuild the stored card |
| `sensitivity_digest_mismatch` | the stored sensitivity analysis is not the one the card signs (`reproduction.sensitivity_digest`), under any release |
| `verification_failed` | an unexpected fault while verifying: nothing vouched for |

`engine_unavailable`, `time_over_budget`, `memory_exhausted` and `invariant_broken`
are step 7b's (section 25.7), with its meanings.

`mythos_core.exposure_receipt`'s codes, as it publishes them (`b1f6e9d`), returned
unchanged:

| Kind | Codes |
|---|---|
| Verdicts (`VERDICTS`) | `authentic`, `forged`, `unknown_key`, `wrong_role`, `wrong_type`, `malformed`, `wrong_card` |
| A malformed envelope or document (`MALFORMED_CODES`) | `envelope_malformed`, `not_json`, `not_canonical`, `wrong_schema`, `unknown_field`, `missing_field`, `wrong_field_type`, `bad_identifier`, `bad_tenant`, `bad_digest`, `bad_instant`, `bad_date`, `bad_integer`, `bad_grade`, `list_not_canonical`, `amount_not_decimal_string`, `amount_malformed`, `amount_precision`, `currency_unknown`, `currency_retired`, `currency_mismatch`, `percentiles_out_of_order` |
| The wrong card (`CARD_CODES`) | `card_malformed`, `card_digest_mismatch`, `card_scenario_mismatch`, `card_grade_mismatch` |
| A keyring refused (`KEYRING_CODES`) | `key_refused`, `key_reused`, `role_invalid` |

`currency_unknown`, `currency_retired` and `currency_mismatch` mean what money's
codes of the same names mean (section 11.5); the tests pin these lists against core.

### 26.8 Safety

Nothing here is on a stop, pause, stand-down, terminate or revoke path, and nothing
in it refuses or delays one. Neither new table has an account column, so removing
an operator (a stop) never writes them; both go with their deployment
(`test_the_records_go_with_their_deployment_and_never_hold_back_a_stop`).
`models.py` imports none of the new modules: the receipt row's check imports
`mythos_core.exposure_receipt` when a receipt is saved, never at load.
`test_django_and_the_urlconf_never_import_the_probabilistic_engine` now also finds
`engine.sensitivity`, `engine.grade`, `validity_service`, `receipt_service` and
`mythos_core.exposure_receipt` unloaded after `django.setup()` and every URLconf, and
`test_a_broken_probabilistic_engine_never_takes_down_the_scan_stop` makes all of them
unimportable before Django loads: the scan's Stop still resolves, answers 202 and is
saved. `tests/test_economics_engine.py` imports both engine modules with Django
poisoned. The engine's signing call is in the effect matrix
(`tests/test_firing_twice_makes_one_effect.py`, `engine-governance`). A failure says
why, as a code, and never raises out of a service.

### 26.9 What is still not done

- **Served by step 6** (section 27): the simulate route issues the card and, when
  asked, the receipt; the report JSON carries the card and the receipt's reference.
- **The engine signs from athena-engine #88** (`POST /api/economics/exposure-receipt/sign`,
  and `roles["economics-receipt"]` in its published keyring), where a deployment
  provisions the role's key and keyring (`ENGINE_ECONOMICS_RECEIPT_KEY`,
  `ENGINE_ECONOMICS_RECEIPT_KEYRING`); an engine without them answers 503 and the
  receipt is `signer_unavailable`, recording nothing. Step 6's simulate route calls
  `issue_receipt` with `engine_keyring()` when the request asks for a receipt.
- **No receipt for a run without a frequency**: core's schema requires an expected
  annual exposure, which such a run does not have (section 25.5), and none is
  estimated. Since step 6 a parameter-set version states the frequency (section
  19.4); only a scenario built from a version that states one can be receipted.
- **A version built before the builder recorded fingerprints has none** (step 8's
  follow-up records it at build, section 24.6): its card still reads the deployment's
  at issue and says so, and a receipt binds that. Nothing refuses a receipt for such
  a version yet (decision 10).
- **No calibration**: "Last calibrated: never; no calibration set exists". Interval
  coverage (the owner's section 26) needs realised outcomes, which no record holds.
- **No source snapshot is a `FinancialSource`.** Parameters name their evidence as
  text (section 22); the receipt's sources are the run's own input snapshots.
- **The evidence names no claim**: claims are not linked to a scenario.
- **The tornado is one at a time**: interactions between parameters are not shown,
  and the swing is per occurrence (times the mean count in an annual run).
- **A per-occurrence parameter of an annual run is neither ranked nor weighed**: such
  a run is graded Unknown (section 26.2) until it is.
- **A sparse-data range is not a downgrade.** A customer range stated as a PERT on
  sparse data (section 23.1) counts as the customer figure it is: a penalty for its
  width would be lifted by collapsing it to its base (section 26.2).

### 26.10 Decisions this step takes, which the owner may change

1. **The ranking is Spearman rank correlation, squared and normalised** (contribution
   to variance, as commercial Monte Carlo tools report it), on the run's own draws.
   Alternatives: Pearson correlation (exact variance shares for a sum, misleading for
   skewed losses); variance-based Sobol indices (interactions shown, but several
   times the draws); regression coefficients. Recommendation: keep it, and add a
   Sobol first-order index for the top drivers if a buyer asks how much interaction
   there is.
2. **The tornado holds every other parameter at its P50, and an annual run's
   frequency at its mean count** (a count's P50 is 0 for a rare event, which would
   flatten every bar). Alternatives: every parameter at its mean; the frequency at
   its P50. Recommendation: keep.
3. **The thresholds** (section 26.2): A at evidence 0.80 and assumption 0.05, B at
   0.50 and 0.25, C at assumption 0.50, D otherwise; material at a level share of 0.05. Alternatives:
   stricter A (evidence 0.90, no assumption at all); grade C on any benchmark share
   above 0.5 regardless of the evidence. Recommendation: keep until calibration data
   exist, and move them with the grade's version.
4. **The classes**: `LICENSED_MARKET` counts as authoritative evidence with
   `OFFICIAL_PUBLIC`; `CALCULATED` (not derived) and `INDUSTRY_BENCHMARK` count as
   neither evidence nor assumption; `UNKNOWN` counts as an assumption.
   Alternatives: licensed market data as benchmark; calculated as evidence.
   Recommendation: keep; revisit when the first licensed feed lands.
5. **A derived value's level share rests on the contributors whose base supplies
   its own** (the larger loss at base), split equally among them where several do,
   and a material one also lowers the grade one step (review round 1). Alternatives:
   count it as `calculated`; split it equally among every contributor; split it by
   how often each gives the larger loss in the draws. Recommendation: keep: the base
   is the figure the level is computed at.
6. **Materiality reads the level share only** (at least 0.05), for the expert and
   derived downgrades; staleness downgrades whatever the share (review round 1, the
   lead's call on H1 was "material by level share OR by importance"). Taken
   literally, the importance path contradicts the required invariant: a wide expert
   range carrying 3% of the level and all of the variance would fire `expert_figures`
   by importance, and collapsing it to its base removes the importance and the
   downgrade, raising the grade one step (the case `a_small_wide_expert_range` of
   `test_collapsing_a_range_to_its_base_never_raises_the_grade`). So the importance
   path is left out, and recorded here for the owner. Alternatives: level OR
   importance, accepting that a collapse can then raise the grade one step;
   materiality by a range's level share at its high end (still removed by a
   collapse). Recommendation: keep the level only.
7. **An unknown MARKET-VALUE component does not make the grade Unknown**; an
   unknown cash component does. Market value is reported apart and never in the cash
   figure the grade is about, and the cross-customer template's share-price line is
   unknown unless public-company data is given. Alternative: any unknown component
   is Unknown. Recommendation: keep.
8. **The grade weighs each figure by its share of the base-case LEVEL** (review
   round 1, H1; the lead's call under the owner's "go with recommendations"), and the
   level is **an additive decomposition at base** (review round 2, HIGH 1; the lead's
   design): each known cash component carries its base over the gross, split among
   its own inputs by their elasticity of it at base, a recovery through its complement
   1 - r as one factor; a frequency carries one half. Fixed figures count exactly as
   ranges; the variance importance only ranks the most sensitive variables. The first
   draft weighed by variance importance and, with nothing uncertain, by count, so an
   expert's fixed $5,000,000 graded A beside a customer range; round 1 weighed by the
   absolute elasticity of the WHOLE gross, normalised, which let a product's factors
   each count their component's whole share and a recovery r count r / (1 - r) of it,
   so an expert lump of 75% to 95% of the level graded A beside a customer recovery of
   0.99 (round 2). Both are removed. **Within a formula that is a sum
   (`fixed_plus_hours`, `per_affected_plus_fixed`) the split is by its additive terms
   first** (step 8's follow-up, the lead's call; sensitivity version 2): each term
   carries its base over the component's, then each term is split among its own
   factors by elasticity -- 1/k each of a product of k, a recovery through 1 - r -- and
   a factor of two terms gets the sum of its parts. #153 split the whole sum by
   elasticity, so a fixed amount F beside a two-factor product P carried F / (F + 2P)
   of the component, not F / (F + P): an expert fixed amount was under-weighted and
   graded better than it should (an expert F of 75% of a component that is 8% of the
   level read 0.048, A; it reads 0.06, C). A sum inside a formula is now weighed
   exactly as the same terms would be as components of their own; every formula of one
   term is split as before, byte for byte. Alternatives: weigh by importance; by the
   share of the mean; give the frequency a share by its own uncertainty; and, the one
   remaining for the split inside a component, **Aumann-Shapley attribution** (each
   input's integral of its marginal contribution along the straight path from zero to
   the base case). For this catalogue it gives the same shares -- a sum of products
   term by term, 1/k to each factor of a product of k; a cap to the cap where it binds
   and to the product where it does not -- and differs only at a cap's exact kink,
   where it is not defined and the elasticity split gives a third each. It needs no
   declared terms, being defined the same way for any formula, at the price of an
   integral per component. Recommendation: keep the attribution by terms (exact, from
   the bases, declared beside each formula and proven against it); take Aumann-Shapley
   if a formula that is neither a sum of products nor a cap joins the catalogue.
9. **The receipt's `parameter_set_digest` is the run's input digest** (every
   parameter the run read, and every version), not the customer parameter-set
   version's content digest, which is among the receipt's `sources`. Alternative:
   the parameter-set version's content digest. Recommendation: keep: the input
   digest is the one that replays the run.
10. **The system fingerprint** is the scenario's where recorded, else the
    deployment's read when the card is issued, labelled so. The builder records one
    at build since step 8's follow-up (section 24.6; the lead's call), so a card of a
    version built since binds the build's state; one it could not compute is none,
    with the reason, and the card falls back as before, naming that reason.
    Alternative: refuse the receipt for a version that records none. Recommendation:
    refuse it once every version a receipt is wanted for has been built since.
11. **The receipt is signed by the engine** on its route
    `/api/economics/exposure-receipt/sign` (athena-engine #88), in the
    `economics-receipt` role: the backend holds no key, as for assurance receipts. A
    document the engine refuses by core's rule is `receipt_refused_by_signer`
    carrying the code, distinct from `signer_unavailable` (the #88 review); a code
    that is not one of core's `MALFORMED_CODES` is shown, never carried as core's
    (review round 2, LOW 6).
    Alternative: a backend-held `economics-receipt` key. Recommendation: keep.
12. **One card and one receipt per simulation result**, made once and kept: the
    review status, inventory entry, findings' status and the deployment's fingerprint
    (read only where the scenario version records none) are as read at issue. Alternative: a new card per issue, superseding the last.
    Recommendation: keep, and let step 6 show the live review status beside the card.
13. **A receipt that cannot be built or signed is not recorded** (unlike step 7b's
    recorded refusals): nothing was signed, and a later issue may succeed.
14. **No signature is recorded unchecked** (review round 1, M2; the lead's call):
    `issue_receipt` requires a `ReceiptKeyring` of the engine's published
    economics-receipt keys and verifies the envelope with core's verifier before the
    row; the row's own check holds core's signature form; a recorded receipt that
    does not verify is not returned and never overwritten. Alternatives: record and
    verify later (the first draft); record the unverified envelope beside a
    `verified: false` mark. Recommendation: keep.
15. **Every figure is evaluated for freshness at the run's as-of date** (review
    round 1, M3; the lead's call): the components', the policy's terms, the
    frequency, every derived value's contributors and the parameter-set variables no
    component reads; a stale policy term lowers the grade where the run applies a
    policy, and so does a stale contributor of a derived value the gross reads; an
    unread variable is shown and does not; nothing is said fresh unevaluated.
    Alternatives: grade staleness of the cash figures only (the first draft); grade
    every stale figure, read or not. Recommendation: keep.
16. **A stored receipt is verified against the release it was made under** (review
    round 1, L7; the lead's call): the card records the release record, the receipt
    names its digest, and a change of today's constants is the note `release_changed`
    on an otherwise authentic receipt, never tampering; the card is rebuilt only
    under its own release, and otherwise the verdict says it was not rebuilt
    (`card_not_rebuilt`) while the stored analysis is still checked against the
    digest the card signs (review round 2, LOW 5). Alternatives: re-verify under today's constants (the first
    draft: every receipt fails on any constant change); keep every past release's
    code to rebuild old cards. Recommendation: keep.
17. **An annual run that draws a parameter per occurrence is Unknown** until such a
    parameter is ranked and weighed (review round 1, L6; the lead's call).
    Alternative: weigh it by its per-occurrence P50. Recommendation: keep; nothing
    names one yet.
18. **Under a policy both lines are graded, and the headline grade is the lower**
    (review round 2, MEDIUM 2; the lead's call): the retained cash's level reads the
    policy's terms (section 26.1), so an expert's deductible or limit that carries the
    retained cash lowers the card's and the receipt's grade, which the gross alone never
    showed. Equal grades give the retained cash's line; a retained cash of zero at base
    (the policy recovers all of it) is Unknown, and so is the headline. The waiting
    period carries one half of the business interruption it leaves uncovered, as one
    factor of it (its elasticity is zero almost everywhere: weighing it by elasticity
    alone would hide an expert's waiting period). Alternatives: one grade on the
    retained cash only; the policy's terms added to the gross line's level; a retained
    cash of zero graded by the gross. Recommendation: keep.
19. **A frequency whose base is zero has no level** (review round 2, LOW 3): a
    base-case year holds no occurrence, so the grade is Unknown, as for a zero gross;
    the frequency is never given a zero share instead, which would hide an expert's
    frequency. Recommendation: keep.

## 27. The scenario endpoints and the report (MVP step 6)

MVP step 6 serves what steps 5, 7b and 8 record: a scenario version with every
parameter's provenance, its validity and its evidence; a simulation of it, run
through step 7b's service with a named simulation policy; and the report JSON of a
stored result, with its loss events, its summary, chart-ready series, the
sensitivity tornado, the grade, the Validity Card and the receipt's reference. A
result graded Unknown is still shown, with the banner the owner adopted, and is
excluded from every total.

| | |
|---|---|
| Code | `assurance/economics/report_api.py` (the three routes), `report.py` (the report and the scenario document; imports nothing probabilistic), `charts_service.py` (the series, a thin Django service) and `engine/charts.py` (pure; imports numpy); `SimulationCharts` in `models.py` |
| Migration | `0067_simulation_charts.py`: one new table, nothing else changed; it depends on #157's `0066_scenario_fingerprint_unavailable.py` (#155, in review, may take a 0067 too: whichever merges second renumbers its own and re-points its dependency) |
| Tests | `tests/test_economics_report.py`; the safety tests of sections 2, 23.10 and 26.8 extended to the new modules; the route tables (`tests/test_economics_scenario_records.py`, `tests/test_every_write_route_keeps_the_decision_current.py`, `tests/test_no_planted_secret_leaves_through_a_sink.py`) and a fault plugin (`tests/economics_broken_report.py`) |

### 27.1 The routes

Under `/api/assurance/`, mounted in a guard of their own (section 2): a fault in
`report_api` or `report` leaves these three routes unserved and nothing else.

| Method and path | Name | Does |
|---|---|---|
| `GET deployments/<uuid>/economics/scenarios/<scenario uuid>/` | `deployment-economics-scenario` | the scenario document (section 27.7) |
| `POST deployments/<uuid>/economics/scenarios/<scenario uuid>/simulate/` | `deployment-economics-scenario-simulate` | runs, or returns, a simulation (section 27.2) |
| `GET deployments/<uuid>/economics/scenarios/<scenario uuid>/results/` | `deployment-economics-scenario-results` | the report of one result: `?simulation=<result uuid>`, else the scenario's latest (section 27.3); never a residual run under a remediation option, which the ROI route serves (section 28.7) |

Access is the parameter-set routes' (section 19.3): a signed-in account (401
otherwise); a deployment the caller cannot see, a scenario of another deployment,
and a result of another scenario are 404; only an admin or an analyst simulates
(403 for a viewer), and every role reads. The simulate body is strict JSON of at
most 64 KiB: a declared length above it is 413 and the parser never reads past it,
a duplicated key is 400, a form is 415. While economics cannot read its currency
table every route answers 503 and records nothing. The report is served as its
canonical bytes (`application/json`), never re-encoded. A route answers no other
method (405).

**The simulate request.** `{"seed": <0 to 2^64 - 1>, "policy": <name>, "receipt":
<bool>}`; only `seed` is required. The seed is a JSON integer or its decimal digits
without a leading zero, at most 20 of them (`seed_malformed`: a longer string is
refused before it is read as a number, so 4,301 digits are a 400, never a 500;
review round 1, LOW-1); the policy is one of section 27.2's
(`policy_unrecognised`, default `standard_100k`); `receipt` is true or false
(`field_malformed`, default false); any other key is `field_unrecognised` and a
missing seed `field_missing`. A refused body records nothing.

**The simulate response.** The request runs `simulation_service.simulate_scenario`
(section 25.7) with the policy's draws and severe percentile over the scenario
version's stored rows -- its source snapshot set is fixed by the version: the
parameter-set version its build names, the build and its own parameters, each with
its content hash (`source_snapshots`) -- and then, once per result, issues its
Validity Card (`validity_service.issue_card`, section 26.4), its chart series
(section 27.4) and, where the body says `"receipt": true` and the run completed, its
receipt (`receipt_service.issue_receipt` with `engine_keyring()`, section 26.5; for
a refused run the engine's keyring is not fetched: `result_not_completed`). A
keyring that cannot be fetched is `keyring_unavailable` with the error's type and
HTTP status only, never its text, which may carry the engine's response body or host
(review round 1, LOW-2), as `signer_unavailable` reports it. It is
IDEMPOTENT: the same inputs, seed and draws return the stored result (200) and never
run a second; a new result is 201. A run the engine refuses is recorded as its
refusal and served so (201, then 200), with no card figures, no series and no
receipt. A run step 7b does not record (`engine_unavailable`, `time_over_budget`,
`memory_exhausted`, `invariant_broken`, `simulation_failed`) is 503, and a request
whose inputs have no identity (a scenario its rows cannot load, a seed or draws step
7a refuses) is 400 with step 7b's code; neither records anything. The response names
the policy, the result (uuid, status, seed, draws, digests, refusal), the source
snapshots, what each issue gave (`issued`, or its code and detail: a card, series or
receipt that cannot be made now is said so and never fails the request) and the
report's URL; the card's grade is its document's, where it verifies (section 27.5).

**ONE deadline** bounds the whole request (review round 1, LOW-5;
`report_api.REQUEST_BUDGET_SECONDS`, step 7b's 120 s): the run, the card's
sensitivity analysis and the series share it, each given what remains, and a stage
with nothing left is not started. Past it the request is 503 `time_over_budget`: the
stage that ran out records nothing (a run past it is not recorded, section 25.7), and
the same request again returns the stored result and issues what is missing. Before,
each stage had its own 120 s, so one request could run three times as long. The
Monte Carlo holds no transaction and no lock (the reviewer measured a stop answering
in milliseconds during a `detailed_1m` run); how many simulations a process runs at
once is not capped yet (section 27.10).

### 27.2 The simulation policies

A run is made under a named policy, as the owner's specification's scenario request
names one (`simulation_policy: standard_100k`):

| Policy | Draws | Severe-but-plausible percentile |
|---|---|---|
| `standard_100k` (the default) | 100,000 | 95 |
| `quick_10k` | 10,000 | 95 |
| `detailed_1m` | 1,000,000 | 95 |

A policy is a name for step 7b's draws and severe percentile, which the result
records; step 7b's limits and time budget (section 25.8) apply unchanged, so a
`detailed_1m` run of a large scenario may be refused for its budget (503, nothing
recorded).

### 27.3 The report

`report.build_report(result)`, schema `mythos.economics.report/v1`, composes ONE
stored result's report from what is stored and only that: the scenario version's
rows, its build, the result, its card and sensitivity analysis, its series and its
receipt. It runs no simulation, reads no clock and asks no engine. Its keys:

| Key | Holds |
|---|---|
| `schema` | `mythos.economics.report/v1` |
| `scenario` | uuid, title, deployment, author, when recorded, the version it supersedes, and the scenario's review status as recorded now (`builder.review_status`) |
| `build` | the build's digest, builder and grouping versions, pack, currency, as-of date and parameter-set version |
| `simulation` | the result's uuid, status, seed, draws, severe percentile, basis, input digest, result digest, outcomes digest, and when it started, finished and was recorded |
| `versions` | every version the run recorded (section 25.6): the engine's, the formulas', the rules', numpy's |
| `model` | the model release the card records: version token and build digest (section 26.5); null where no card is recorded |
| `source_snapshots` | the version's source snapshots with their content hashes recomputed, or why not (`source_snapshot_mismatch`) |
| `currency` | the reporting currency, its minor unit and the rounding (section 27.5) |
| `status`, `refusal` | the run's status, and a refused run's code and detail; for a result whose stored rows fail a check, the code `stored_row_unverified` naming the checks (section 27.5) |
| `integrity` | `verified`, the checks run (`report.INTEGRITY_CHECKS`) and those failed (section 27.5) |
| `grade`, `banner`, `excluded_from_totals`, `banner_reason` | section 27.6; the grade is the card DOCUMENT's, never the column's |
| `loss_events` | each event (key, currency, effect, business process, trigger) with its components, in component-key order (review round 1: the order the rows were inserted in, which step 7b's inputs keep, never changes a report) -- family, formula and version, status, low, base and high, the reason an unknown one is unknown and what it misses, and `reads`: the parameter each input reads -- and its gross cash, retained cash under a policy and market value at low, base and high, each saying whether it is complete; market value is `never_added_to_cash` |
| `parameters` | every parameter the run read, as its canonical inputs hold it, with `read_by`: each component input, policy term, frequency or derived value that reads it |
| `summary` | the basis and its statement; for each line (gross cash, retained cash, market value) P10, P50, P90, mean, expected annual loss and severe-but-plausible, the standard error of the mean and each figure's band at the run's confidence level; for an annual run the per-occurrence lines beside; `not_reported` on every figure, band or line that does not exist, with the reason (no frequency: no expected annual loss; an infinite mean or variance: no mean, standard error or band; no policy: no retained cash; no market-value component) |
| `charts` | the stored series (section 27.4) with their digest, or why there are none |
| `sensitivity` | the stored analysis (section 26.1): its digest, method, basis, baseline, and the tornado, every ranked parameter with its rank, importance, direction, P10, P50 and P90 (a money parameter's at the minor unit, section 27.5; any other's as the analysis has them), and its low and high outcomes; the fixed parameters and statements |
| `validity_card` | the card's digest, schema, issue time, grade, model version, reviewer status at issue, and its non-money fields as stored (`confidence_grade`, the three shares, `last_calibrated`, `data_freshness`, `system_fingerprint`, `technical_evidence`, `unknown_variables`, `reproduction`); the card's figures and most sensitive variables are the report's `summary` and `sensitivity` at the minor unit, and the whole card is the stored record its digest names |
| `receipt` | a reference, marked `verified: false`: the receipt id, key id, generation time, the document's digest and the card digest it signs; the signature is verified by `receipt_service.verify_stored_receipt` (section 26.6), not by the report |
| `limitations` | the eight statements of `report.LIMITATIONS`, in every report |
| `unknowns` | every unknown component with its reason and missing inputs, a refused run's refusal, and an integrity refusal's failed checks |
| `digest` | section 27.5 |

**A refusal is served as the refusal**, never as figures: a refused run's report has
its refusal, its events and components with every amount null, and `summary`,
`charts` and `sensitivity` each `not_reported` with the reason. Its `parameters` are
still served: they are what was entered (a lump sum's low, base and high among them),
not results (review round 1, LOW-6; an owner note, section 27.11). A result's report
can gain a card later, as it can gain a review: between the result's insert and its
card's, it reads "not graded", with the banner, which is the conservative answer.

### 27.4 The chart series

`engine/charts.py`, schema `mythos.economics.charts/v1` version 1
(`charts.version_record()`, in every record), made on the run's OWN draws as the
sensitivity analysis is (section 26.1): the scenario version's canonical inputs must
give the run's input digest (`inputs_changed`) and the draws, made again from the
same seed and sub-streams, the run's outcomes digest (`result_not_reproduced`). For
each line the run summarised -- gross cash, retained cash under a policy, market
value where known -- per simulated year where the run has a frequency
(`annual_loss`), per occurrence otherwise:

- **The exceedance curve** at the probabilities 0.5, 0.2, 0.1, 0.05, 0.02, 0.01,
  0.005, 0.002 and 0.001: the loss exceeded with probability p is the line's type 7
  quantile at 1 - p (step 7a's, of the run's sorted draws), with the draws beyond
  it. A point is reported only where the run has at least 10 draws beyond it (n p >=
  10); otherwise its loss is null and `not_reported` says why: a tail the draws do
  not reach is never extrapolated.
- **The histogram**: 40 equal bins from zero to the line's P99, each bin's width
  rounded UP to the currency's minor unit (one minor unit at least), so every edge
  is a whole number of minor units; one open bin above the last edge holds the
  tail. A bin holds the draws `lower <= x < upper`; the counts sum to the draws.

`charts_service.issue_charts(result)` records the series once per result as a
`SimulationCharts` row: append-only, with no account column, going with its
deployment: the deployment, the scenario, the result (ONE-TO-ONE), the schema, the
series and their digest. Every check -- the tenant, the result's scenario,
completed, the series' schema and identity (scenario, seed, draws, input and
outcomes digests) the result's, no float, the digest -- runs before the
transaction, which only inserts; a row that fails is `charts_record_malformed`, and
two issues racing past the lookup are stopped by the one-to-one key. The service
**never raises**: a failure the stored rows do not decide (`result_not_completed`,
`engine_unavailable`, `inputs_changed`, `result_not_reproduced`,
`time_over_budget`, `memory_exhausted`, `invariant_broken`, `charts_failed`) is
returned and never recorded. The report reads the stored series, checks them
against their digest and their result first (section 27.5), and never draws
them: a result recorded before step 6 has none until it is simulated again (the
same request returns the stored result and issues what is missing).

### 27.5 Determinism, money and the digest

**The same stored rows give byte-identical reports.** The report is canonical JSON
(`report.canonical_bytes`: sorted keys, no whitespace, ASCII, no float, no NaN),
every list is in an order the rows fix (events by key, parameters by name, results
by record order), and the only times in it are stored ones: when the scenario was
recorded, when the run started, finished and was recorded, when the card was issued
and when the receipt was generated. A key order the stored JSON happens to hold
changes nothing. `digest` is `sha256:` and the SHA-256 of the canonical bytes of the
report without it (`report.digest_of`, `report.verifies`), so a reader recomputes it
from the bytes served.

**Every stored row is checked before it is served** (review round 1, MEDIUM-1;
`report.stored_row_failures`, plain hashing, no engine): a report's digest covers
what it serves, so it must not serve a row that is no longer as recorded. In order
(`report.INTEGRITY_CHECKS`):

| Check | Holds |
|---|---|
| `input_digest` | the result's stored inputs give its input digest |
| `result_digest` | a completed result's record gives its result digest; a refused one holds none |
| `card_digest` | the card's document gives its card digest |
| `card_grade` | the card's grade COLUMN is the grade its DOCUMENT states (the column is outside the digest), and a grade of the card's vocabulary |
| `card_result` | the card is the result's (its row's result, scenario and deployment) and its reproduction names the result's seed, draws, input digest and result digest |
| `sensitivity_digest` | the stored analysis gives the digest the card signs, and the column holds it |
| `charts_digest` | the series give their digest, of their schema |
| `charts_result` | the series are the result's: their row's result, scenario and deployment, and the scenario, seed, draws, input digest and outcomes digest they name |

A result whose rows fail any check is served as a refusal: `refusal.code`
`stored_row_unverified` naming the checks, no figure (every amount null, `summary`,
`charts` and `sensitivity` not reported), the banner and `excluded_from_totals:
true`. A card that fails a check counts as no card (the result is not graded), and
series that fail one are not served. The grade the report, the scenario document and
the simulate response state is always the card document's, and only where the card
verifies (`report.verified_grade`). The reviewer's repros -- a grade column edited
from Unknown to A, a record's P50 edited, a histogram bin inflated, a series moved
to another result -- are each a test.

**Money at the currency's minor unit.** Every amount of loss the report states -- a
component's and an event's low, base and high, the summary's figures, standard
errors and bands, the series' losses, edges and widths, the tornado's baseline and
outcomes, and a money parameter's P10, P50 and P90 in the tornado (quantiles the
analysis computed, not recorded figures; review round 1, LOW-3) -- is the stored
amount rounded half-even to the reporting currency's minor
unit (`Money.display_amount`, section 11.3), as a decimal string: 0 places for JPY,
2 for USD, 3 for KWD. A parameter's own figures are shown as recorded, since a cost
per unit may lie below the minor unit (USD 0.375 a record). The stored result, card
and analysis keep full precision; the report never feeds a rounded figure back.

### 27.6 Unknown: not for capital decisions

A result graded Unknown is shown with whatever figures it has, and carries the
banner `Unknown: not for capital decisions` (its `banner` key) and
`excluded_from_totals: true`.
The same holds for a refused run and for a result with no Validity Card, which is
not graded; `banner_reason` says which. A graded result (A to D) has `banner: null`
and `excluded_from_totals: false`.

Nothing may sum an excluded result into a total. `report.may_be_totalled(report)` is
the one test a total applies, and it **fails closed** (review round 1, LOW-4): true
only for a report that carries the digest of its own bytes (`verifies`), of a
completed result whose rows verified, `excluded_from_totals` false, and graded A, B,
C or D (`report.GRADES_FOR_TOTALS`, an allow-list). A forged, edited or stale report
is refused, and so is one re-digested with an Unknown grade. A total of several
reports leaves out every one it refuses. No route serves a total yet (section
27.10).

### 27.7 The scenario document

`report.scenario_document(scenario)`, schema `mythos.economics.scenario/v1`: the
scenario (as section 27.3), its build, and:

- `parameters`: every parameter of the scenario version and of the parameter-set
  version its build names, each with its provenance: its parent (the scenario, or
  the set key and version), unit, currency, low, base and high as recorded, source
  type, evidence reference, effective date, `fresh_until`, the distribution it
  states, the parameters it was derived from, and `read_by` (each component input,
  policy term or frequency that reads it; a parameter nothing reads has none);
- `frequency`: the scenario's frequency parameter's name, or null;
- `validity`: each simulation result of the version (uuid, seed, draws, status,
  refusal code, when recorded) with its card's grade (the document's, null where
  there is no card or it does not verify: `card_verified`) and digest, whether its
  series are recorded, and its receipt id;
- `evidence`: the SPINE evidence as ids, never copies (`spine_evidence`, the
  receipt's), each effect's key, origin, observed effect, observation, SPINE effect,
  asset and loss event, and each enabling finding's id, effect and role.

### 27.8 Codes

New codes: `seed_malformed` (a seed that is not a whole number from 0 to 2^64 - 1, as
a JSON integer or at most 20 digits), `policy_unrecognised` (a policy section 27.2
does not name), `stored_row_unverified` (a result whose stored rows fail a check of
section 27.5: served as a refusal, never as figures), `charts_record_malformed` (a series row that is not its own completed
result's series: another scenario or tenant, a refused result, another schema or
identity, a float, a digest that is not the series'), and `charts_failed` (an
unexpected fault while making a series: nothing recorded). `field_missing`,
`field_unrecognised` and `field_malformed` are the parameter-set API's (section
19.3); `inputs_changed`, `result_not_reproduced`, `result_not_completed` and
`keyring_unavailable` are step 8's (section 26.7), and the run's codes step 7b's
(section 25.7), each with its meaning; `time_over_budget` is also the simulate
request's own, when its one deadline runs out (section 27.1).

### 27.9 Safety

None of the three routes is a stop, and none reads or writes anything a stop or the
decision reads: each is in `safety.stops.NOT_STOPS` (the simulate route: "economics
records, append-only; it starts and stops nothing"). The simulate route is in the
write-route table of `tests/test_every_write_route_keeps_the_decision_current.py`
as one that cannot move the decision, and every route is a classified sink of the
canary harness. `SimulationCharts` has no account column, so removing an operator
(a stop) never writes it. `report_api` imports the simulation, card, series and
receipt services only inside a view, and `report` only inside a function:
`test_django_and_the_urlconf_never_import_the_probabilistic_engine` finds
`engine.charts` and `charts_service` unloaded after `django.setup()` and every
URLconf, and `test_a_broken_probabilistic_engine_never_takes_down_the_scan_stop`
makes them unimportable before Django loads. A broken `report` module
(`tests/economics_broken_report.py`) leaves the three routes unserved while the
parameter-set and builder routes resolve and the scan's Stop answers 202 and is
saved (`test_a_report_fault_never_takes_down_a_stop`).

### 27.10 What is still not done

- **No total across scenarios or deployments.** `may_be_totalled` is the rule any
  later total must apply; nothing sums reports yet.
- **A range that states no distribution is still refused** (section 25.1): the
  parameter set and the builder now write distributions and the frequency (section
  19.4), but a stored scenario whose customer, benchmark or observed range states none
  is refused by its run, and the report serves that refusal as a refusal.
- **A receipt is signed only when asked** (`"receipt": true`) and only where the
  engine publishes an `economics-receipt` key (section 26.9); otherwise the report
  says no receipt is recorded.
- **The report is JSON only**: no PDF, no rendered page, no frontend chart.
- **The scenario document lists every result** of a version, unpaginated.
- **The live review status** is read when the report is built: a review recorded
  later changes the report's bytes and digest, as it should (the card keeps the
  status at issue).
- **No cap on simulations at once** (review round 1, LOW-5): one request is bounded
  by its one deadline, but how many a process runs at once, or a scenario holds, is
  not. Open for the testing phase: a per-process cap (503 when busy), so a pool of
  synchronous workers cannot fill with long simulations a stop's request might need.
- **The step-5 events route** (`.../scenarios/<uuid>/events/`, section 24.8) serves a
  scenario's deterministic totals with no banner, even where its result is graded
  Unknown; it says `complete: false` and "at least: the known components only".
  A follow-up carries the banner there too (review round 1, LOW-6(b)); this step
  does not change that route.

### 27.11 Decisions this step takes, which the owner may change

1. **The chart series are stored** (`SimulationCharts`, one per result), made once
   when a simulation is requested, never when a report is read. Alternatives: draw
   them on every GET (numpy and the run's whole cost on a read path); add them to
   step 7b's record (changes its result digest for every stored run).
   Recommendation: keep.
2. **The banner is shown, and the result excluded from totals, when the grade is
   Unknown, the run was refused, or no card is recorded.** Alternative: only when
   graded Unknown. Recommendation: keep: an ungraded figure is no better evidence
   than an Unknown one.
3. **A receipt is signed only when the request asks.** Alternative: always sign on
   simulate. Recommendation: keep until every engine publishes the
   `economics-receipt` role, then make it the default.
4. **Three named simulation policies, each at the 95th percentile.** Alternatives:
   free draws and percentile in the request; a policy per deployment.
   Recommendation: keep; add a policy when a buyer asks for another percentile.
5. **Loss amounts are shown at the minor unit; a parameter's figures as recorded.**
   Alternative: every figure at the minor unit (a unit cost of USD 0.375 would show
   as 0.38 and no longer reproduce the components). Recommendation: keep.
6. **The report carries the card by digest and its non-money fields**; the card's
   figures and drivers are the report's summary and tornado at the minor unit.
   Alternative: embed the whole card at full precision. Recommendation: keep: one
   figure per quantity in a report.
7. **`results/` without `?simulation=` serves the version's latest result**, by
   record order. Alternative: require the result's uuid. Recommendation: keep.
8. **The exceedance curve is read at nine fixed probabilities and needs ten draws
   beyond a point; the histogram has 40 bins to P99.** Alternatives: return periods
   chosen by the request; more bins. Recommendation: keep, and move them with the
   series' version.
9. **A result whose stored rows fail a check is served as a refusal**
   (`stored_row_unverified`), and a card that fails one counts as no card (review
   round 1, MEDIUM-1, the lead's call). Alternative: drop only the failing part (a bad
   series not reported, a bad card ungraded) and serve the rest. Recommendation: keep:
   a row that no longer gives its digest says the stored state was changed outside
   the code, and none of that result's figures is then evidence.
10. **One deadline per simulate request**, step 7b's 120 s shared by the run, the
    analysis and the series (review round 1, LOW-5, the lead's call); past it, 503,
    nothing more recorded, and a retry issues what is missing. Alternative: a
    deadline per stage (the first draft: up to three times as long). Open: a cap per
    process, for the testing phase (section 27.10).
11. **`may_be_totalled` fails closed**: the report's own digest, its rows verified,
    and an allow-list of grades A to D (review round 1, LOW-4). Alternative: a block
    list of Unknown (the first draft). Recommendation: keep.
12. **A refused run's report keeps its recorded inputs** (review round 1, LOW-6(a),
    an owner note): its `parameters` are what was entered, not results, though a lump
    sum's are its component's low, base and high. Alternative: null every money
    parameter of a refused run. Recommendation: keep, so the refusal can be read and
    the inputs corrected.

## 28. One remediation option, its residual run and its economics (MVP step 13)

MVP step 13, on steps 7b, 8 and 6: ONE remediation option per scenario version, the
residual run of the scenario with the option's control effect, and the option's
economics (the owner's specification, section 21, Remediation Economics; section 18's
`POST /financial/scenarios/{id}/mitigations` and `GET .../roi`; section 15's
`MitigationOption` and "Mitigation PRODUCES ResidualExposure"), with the hard security
veto, which always wins.

| | |
|---|---|
| Code | `assurance/economics/engine/remediation.py` (pure: the option's form and digest, the economics); `assurance/economics/engine/scenario_simulation.py` (the residual run: `Remediation`, the reduction factor) and `engine/sensitivity.py` (a residual run's reductions ranked and swung); `assurance/economics/remediation_service.py` (the record, the runs, the veto, the citations, the ROI document) and `remediation_api.py` (the three routes); `RemediationOption` and `SimulationResult.remediation` in `models.py` |
| Migration | `0068_remediation_options.py`: one new table and one new nullable column on `SimulationResult`; nothing backfilled, every stored run unchanged. #155 (the trust tier, in review) is expected to take a 0068 too: whichever merges second renumbers its own and re-points its dependency |
| Tests | `tests/test_economics_remediation.py`; the route tables (`tests/test_economics_scenario_records.py`, `tests/test_every_write_route_keeps_the_decision_current.py`, `tests/test_no_planted_secret_leaves_through_a_sink.py`), the engine's module and code tables (`tests/test_economics_engine.py`) and a fault plugin (`tests/economics_broken_remediation.py`, `tests/economics_fault_cases.py`) |

### 28.1 The option

`RemediationOption`, append-only, ONE per scenario version (a one-to-one key, and
`remediation_option_held`): a different option is a new version that supersedes the
old, and the same option posted again returns the one recorded. Its document
(`mythos.economics.remediation-option/v1`, `engine.remediation.parse_option`):

| Field | Holds |
|---|---|
| `title` | 1 to 255 characters |
| `implementation_cost`, `recurring_cost` | money, as a parameter set's variable is stated (unit `money`, low, base, high, currency, `source_type`, `evidence_ref`, `effective_date`, optionally `fresh_until`); one currency, the scenario's (`currency_mismatch`: nothing converts here); never `MYTHOS_OBSERVED` (`observed_source_not_observable`); the recurring cost is a year's |
| `time_to_implement_days` | a whole number from 0 to 3,650 |
| `dependencies` | at most 20, each text (1 to 500 characters) or a SPINE finding or asset of the deployment by its uuid, never a copy (`dependency_malformed`, `dependency_not_found`) |
| `control_effect` | `frequency_reduction` `r_f` and/or `magnitude_reduction` `r_m` (`control_effect_missing` otherwise), each a ratio in [0, 1] with low, base, high, source and evidence, optionally a stated distribution; `acts_on`: every component (absent), or the loss families or the scenario's components (`<event key>/<component key>`) it names, one or the other (`acts_on_malformed`, `remediation_target_unknown`); `observed_by`: the retest it was observed in (section 28.6) |
| `utility_evidence` | optionally, the retest cited for utility retained (section 28.3) |

Each reduction must be admitted by the run's own parameter-to-distribution rule
(section 25.1) when it is written: a point mass for a fixed figure, PERT for an
`EXPERT_ESTIMATE` range, a stated distribution that holds its figures; any other range
is refused then (`no_admissible_distribution`), not when it is run. The option's
identity is `option_digest`: the SHA-256 of the canonical JSON of its schema, its
scenario version and its document in the one spelling; the row's check re-reads the
document and its digest on save (`remediation_record_malformed`). It names its author as
a scenario does: the signed-in admin or analyst, nulled if the account is removed (a
stop), the username kept.

### 28.2 The residual run

The SAME engine, seed and draws, with **common random numbers**: a residual run
(`ScenarioInput.remediation`) draws every parameter, the frequency and every derived
value from exactly the current run's streams, so current minus residual carries little
Monte Carlo noise of its own, and a component the option does not act on is the current
run's, draw for draw. The reductions draw from streams of their own (`r` and 40 hex
digits of the SHA-256 of `mythos.economics.remediation-stream/v1`, a zero byte and the
role), never a parameter's, so drawing the control effect moves no parameter's draws.

- `r_f` and `r_m` are each resolved by the parameter-to-distribution rule and drawn once
  per simulated year (once per draw without a frequency), as every shared parameter is.
- **Frequency**: each occurrence of a component the option acts on is kept where a
  uniform draw from its own stream (`remediation.kept`) is below `1 - r_f`, its year's
  `r_f`: the expected count of occurrences it suffers is the frequency times
  `1 - r_f`. A whole occurrence is stopped, not a fraction of a count. A frequency
  reduction on a scenario that states no frequency is refused, and recorded
  (`remediation_needs_frequency`): a run per occurrence has no frequency to reduce.
- **Magnitude**: each kept occurrence of such a component is multiplied by `1 - r_m`.
- Insurance applies after, to what remains, per event occurrence as section 25.4 says.
- A reduction that is a point mass at zero changes nothing: the residual run of
  `r = 0` IS the current run, its summaries byte-identical (only its input digest and
  its record's `remediation` block differ). A component the option changes is no longer
  exact (section 25.3): its summary is of its draws, and it is marked `remediated`.

The residual run is a stored `SimulationResult` whose canonical inputs are EXACTLY the
current run's with one key added, `remediation` (`mythos.economics.remediation-run/v1`:
the option and its digest, each reduction with its figures, source, evidence and stated
distribution, what it acts on, its streams and the rule), so it never collides with the
current run's result, and the current run's input digest is the digest of the residual
run's inputs without that key. Its row names the option (`SimulationResult.remediation`,
checked against the inputs on save). A run with no option has no such key: every input
digest recorded before this step is unchanged. Every limit, the 120 s budget, the
idempotency and the insert-only transaction of section 25.6 apply; the values budget
counts the residual run's factor, its uniform draws and a reduction's draws per
occurrence (`REMEDIATION_TEMPORARIES`). NO transaction or lock is held during either
Monte Carlo (`test_no_transaction_is_held_while_either_run_computes`).

Each run is graded by its own Validity Card (section 26): a residual run's analysis is
made on its own draws with the option applied, ranks a drawn reduction as it ranks a
parameter, and swings each through the factor it puts on a reduced component.

Known answers on step 6's fixed scenario (`stored`: one event of a notification and a
regulatory range, a Poisson(2) frequency): `r_f = 0.5` halves the expected annual loss
within four of the residual run's standard errors; `r_m = 0.25` on every family cuts it
to three quarters to binary64's rounding (1E-12 relative), and P50, P90 and P95 with
it; `r = 0` gives a reduction of exactly zero and byte-identical summaries; `r = 1` on
every family leaves a residual expected annual loss of 0.

### 28.3 The economics

`GET .../roi/` serves the ROI document (`mythos.economics.roi/v1`), from stored rows
only, of the option and one residual run (`?simulation=<uuid>`, else its latest) paired
with its current run. Every figure is read at full precision from the two runs' records
(the result digest covers them) on their headline line -- retained cash under a policy,
else gross cash, as the card and the receipt read it -- and computed once:

| Output | Definition |
|---|---|
| `current_expected_annual_exposure`, `residual_expected_annual_exposure` | each run's mean annual loss |
| `expected_reduction` | current minus residual |
| `first_year_investment` | implementation plus one year of recurring cost, at low, base and high |
| `risk_adjusted_roi` | the expected reduction over the first-year investment at base, to 4 places; labelled decision support from modelled exposure, not a guaranteed return; `null` with the reason where the investment is 0 |
| `payback` | the first-year investment at base over the expected annual reduction, in years, to 2 places; `null` with the reason where the reduction is not above zero: never a negative or infinite payback |
| `tail_reduction` | the change in P90 and in P95 (the severe-but-plausible percentile, where the run's is 95) of annual loss |
| `utility_retained` | `retained` or `broken` from a cited retest's replay (legitimate use, and every behaviour its repair contract preserves); otherwise `unknown`, with the reason |
| `confidence_delta` | the residual card's grade against the current card's, each as its card document states it where it verifies (section 27.5): `improved`, `unchanged`, `worsened`, or `not_comparable` with the reason |

Money is at the currency's minor unit, half-even, as section 27.5 rounds it; the ROI and
the payback are half-even to their places. Without a frequency there is no expected
annual exposure, so no reduction, ROI or payback, each saying so. The document carries
the option (its costs and control effect as recorded), each run's identity, status,
grade, banner reason and integrity, the line, the currency, `limitations` and `digest`:
`sha256:` over its canonical bytes without it, as section 27.5's report does. The same
stored rows give byte-identical bytes.

### 28.4 The hard security veto (decided: the veto always wins)

The owner's specification: a strong ROI does not justify accepting a control failure
that Mythos policy marks as a hard release blocker. `remediation_service.veto` reads it
from SPINE as it stands when the document is built:

- a **finding** the scenario rests on (`EffectFinding`) is a hard release blocker where
  Mythos policy places a deployment holding it in a blocking decision: active (not
  closed, accepted or a false positive), of trusted severity, and high or critical,
  which `assurance.decision.FINDING_SEVERITY_DECISIONS` places at `needs_remediation` or
  `not_recommended` (`assurance.dispatch`'s blocking decisions);
- an **observed effect** of the scenario is one where its workflow's chain is violated
  and sets the deployment's composition at `not_recommended`
  (`assurance.workflow_chains.composition_for`, its deciding workflows).

`veto.applies` is `true` where one is: the document carries `veto: {"applies": true,
"reason": ...}`, `remediation_required: true` and the statement
"remediation is required regardless of ROI"; the ROI and the payback are
`display_only`, and no output presents accepting the risk as preferable. Where the blocker status cannot be read -- an
invalidated finding (its severity no longer trusted), one that is no longer the
deployment's, a severity Mythos policy does not read, an observed effect whose SPINE
outcome cannot be found, a scenario naming neither, or any fault reading SPINE (named
by its type alone) -- `veto.applies` is `"unknown"`, with the reason, and it is treated
as applying. `false` only where every finding and observed effect was read and none is
a blocker.

### 28.5 Unknown: the banner

Each run is verified as step 6's report verifies a result: the ROI document builds each
run's report (`report.build_report`) and reads its `grade`, `banner_reason`,
`integrity` (`report.stored_row_failures`) and whether a total may sum it
(`report.may_be_totalled`). Where the current or the residual run is Unknown, refused,
card-less or unverified -- or the option no longer gives its digest, the residual run
names another option, no current run of the same seed and draws is recorded, or the
control effect's cited retest no longer shows the control held -- the document carries
the step-6 banner, `Unknown: not for capital decisions`, and
`excluded_from_totals: true`, with the reason. Figures are shown where both runs completed and every row
verifies; no ROI is computed on a refusal or on rows that fail a check (`not_reported`,
with the reason). The document has `status`, `grade` (the lower of the two runs'),
`excluded_from_totals`, `integrity` and `digest` as a report does, so
`report.may_be_totalled` is the one test a total applies to it too, and it fails closed.

### 28.6 An observed control effect

A control effect may cite an Achilles retest, a `RetestClosureEvidence` record (the
replay of Minotaur-Backend's remediation-outcomes dataset, `assurance.retest_closure`),
by its digest: the SHA-256 of `mythos.economics.retest-citation/v1`, the record, its
finding and everything the retest gate reads of it (origin, content digest, fixtures,
document, time; `remediation_service.retest_digest`). The citation is resolved among the
records of the findings the scenario rests on, in its deployment only.

- **Cited and verifiable, where the retest shows the control held**: the record is its
  finding's latest and the retest gate's own verdict (`retest_closure.refusal_reasons`)
  names no reason -- every fixture class and pattern ran with the outcome a closure
  needs, an independent observer's replay shows the effect gone on the original
  scenario and every variant with legitimate use retained, held to the finding's
  current repair contract. Then the control effect is observed: every reduction it
  states rests on `MYTHOS_OBSERVED` (`observed_effect_not_stated` otherwise), and a
  reduction on `MYTHOS_OBSERVED` cites one (`observed_effect_uncited` otherwise).
- **Cited but unverifiable**: refused, `retest_unverifiable`; a retest that is found but
  does not show the control held is refused, `retest_control_not_held`, naming every
  reason the gate gives.
- The ROI document verifies the citation again when it is built: a later retest of the
  finding (the gate reads the latest) that was fooled leaves the observed effect
  unverified, and the document carries the banner.

No Bayesian update yet: an observed control effect is cited, verified and shown as
observed, and its figures are as stated (section 28.9).

### 28.7 The routes

Under `/api/assurance/`, from `assurance/economics/remediation_api.py`, mounted in a
guard of its own (section 2): a fault in it, or in `remediation_service`, leaves these
three routes unserved and nothing else (`test_a_remediation_fault_never_takes_down_a_stop`).

| Method and path | Name | Does |
|---|---|---|
| `POST deployments/<uuid>/economics/scenarios/<scenario uuid>/mitigations/` | `deployment-economics-scenario-mitigations` | records the version's one option: 201; the same option again, 200; another, 409 `remediation_option_held` |
| `POST .../mitigations/<option uuid>/simulate/` | `deployment-economics-mitigation-simulate` | the current run (where missing) and the residual run, `{"seed", "policy"}` as section 27.1's simulate takes them (a `receipt` is `field_unrecognised`: a residual run is not receipted), each with its Validity Card, under ONE 120 s deadline: idempotent, 201 where a run was recorded, 200 where both were; 503 for a run step 7b does not record, 400 for inputs with no identity |
| `GET .../scenarios/<scenario uuid>/roi/` | `deployment-economics-scenario-roi` | the ROI document (section 28.3), as canonical bytes; 404 where the version has no option or the option no residual run |

Access is the report routes': a signed-in account; a deployment the caller cannot see,
or a scenario, option or run of another, is 404; only an admin or an analyst records or
simulates (403 for a viewer, even the owner), and every role reads. Strict JSON of at
most 64 KiB; 503 while economics cannot read its currency table, recording nothing.

**A residual run is never the scenario's exposure.** Step 6's `results/` route serves
only the version's own runs (its latest is the latest of those, and a residual run's
uuid is 404 there), and the scenario document lists only those; the ROI route serves the
residual run.

### 28.8 Safety

No route here is a stop, and none reads or writes anything a stop or the decision reads:
each is in `safety.stops.NOT_STOPS`; the two POSTs are in the write-route table as
routes that cannot move the decision; all three are classified sinks of the canary
harness. The veto reads findings and chains; it writes nothing. `RemediationOption`'s one
account column is SET_NULL, so removing an operator answers 204 and keeps the username
(`test_removing_the_author_never_writes_more_than_the_account_column`); the option and
the residual runs go with their deployment. `remediation_api` and `remediation_service`
import no part of the probabilistic engine at load: the simulation and card services are
imported when an option is simulated, and the engine when an option is written. Each
service transaction only inserts, after its run.

### 28.9 What is still not done

- **No Bayesian update** of the control effect from observed evidence: an Achilles
  retest is cited and verified, and Minotaur validation is not read yet.
- **One option per scenario version**: no cost-of-fix frontier across options, and no
  portfolio of options.
- **The costs are not simulated**: the ROI and the payback read the base; no net
  present value, no multi-year horizon, no discounting.
- **The control effect's evidence does not enter the residual card's grade**: both cards
  weigh the scenario's figures (section 26.2), so the confidence delta moves only where
  a card is Unknown, missing or unverified. Weighing the reductions in the residual
  line's level -- `(1 - r_f)` beside the frequency's half, `(1 - r_m)` as one more factor
  of each reduced component -- is the follow-up.
- **No green-team evidence** exists in this backend: utility retained reads a cited
  Achilles retest's replay, else Unknown.
- **One currency**: an option costs in the scenario's currency; nothing converts.

### 28.10 Decisions this step takes, which the owner may change

1. **One option per scenario version**, a one-to-one key; another option is a new
   version. Alternative: several options per version, for a frontier.
2. **A frequency reduction stops whole occurrences** of the components it acts on (a
   keep mask, Bernoulli `1 - r_f`, from its own stream). Alternatives: scale the
   frequency's rate (Poisson((1 - r_f) lambda)), which numpy draws from other numbers,
   losing the coupling; multiply each year's loss by `1 - r_f`, which keeps the mean and
   understates the tail's change.
3. **The reductions are drawn once per simulated year**, as every shared parameter
   (section 25.2), each by the existing parameter-to-distribution rule, and admitted at
   write time. Alternative: per occurrence.
4. **A frequency reduction on a scenario with no frequency is refused** and recorded.
   Alternative: read it as the probability an occurrence is prevented, a mixture with
   zeros in a per-occurrence run.
5. **ROI = expected reduction / first-year investment at base** (4 places), **payback =
   first-year investment at base / expected annual reduction** (2 places), half-even;
   the investment's range is shown, not swept. Alternatives: a net ROI ((reduction -
   investment) / investment); ROI at each point of the investment; a multi-year NPV.
6. **The headline line** (retained under a policy, else gross cash) for every figure,
   as the card and the receipt. Alternative: gross cash always.
7. **The confidence delta compares the two cards as recorded**; the control effect's
   evidence does not weigh in a grade yet (section 28.9). Alternative: weigh it now,
   in a new sensitivity and grade version.
8. **A residual run's sensitivity ranks its drawn reductions and swings them through
   their factor**, without a new sensitivity version: no analysis of a run without an
   option changes, byte for byte. Alternative: a new version for every card.
9. **The veto reads findings by Mythos policy's severity rule and observed effects by
   their chains**: high or critical and active vetoes; closed, accepted or false-positive
   does not; invalidated, missing or unreadable is `"unknown"`, which applies.
   Alternatives: veto on an accepted finding too; veto on the deployment's standing
   decision (any blocking decision vetoes every scenario of it).
10. **Under the veto the ROI and the payback are shown, display-only**, with the
    statement. Alternative: withhold them.
11. **The banner** where either run is Unknown, refused, card-less or unverified, where a
    row of the pair fails a check, or where the cited retest no longer verifies.
12. **A retest is cited by a digest over the record and everything the gate reads**, and
    verified by the gate's own verdict on the finding's latest record. Alternatives:
    cite the record's `content_digest`; accept any record whose replay classifies
    `verified_closed`.
13. **An observed control effect is all-observed**: every reduction `MYTHOS_OBSERVED`
    with a verified citation, and the reverse. Alternative: per-reduction citations.
14. **A residual run is not served by `results/` or the scenario document**, and not
    receipted. Alternative: serve its report too, marked residual.
15. **The simulate route issues each run's Validity Card, not its chart series**: the
    ROI reads the grade only. Alternative: issue the series too, as step 6's simulate.
