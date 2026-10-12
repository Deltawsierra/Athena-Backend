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
and records the result, and serves no route.

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
20. [The scenario records](#20-the-scenario-records)
21. [Known-answer fixtures](#21-known-answer-fixtures)
22. [Limitations of the scenario engine, and decisions for the owner](#22-limitations-of-the-scenario-engine-and-decisions-for-the-owner)

Phase E2, MVP step 7a, after the scenario engine's sections 14 to 22 (MVP step 4):

23. [Distributions and simulation](#23-distributions-and-simulation)

The scenario builder, MVP step 5 (merged after step 7a):

24. [The scenario builder (MVP step 5)](#24-the-scenario-builder-mvp-step-5)

Phase E2, MVP step 7b, wiring step 7a to steps 4 and 5:

25. [Wiring the simulation (MVP step 7b)](#25-wiring-the-simulation-mvp-step-7b)

## 1. Status and scope

| | |
|---|---|
| Phase | E0: taxonomy, source registry, model governance, currency rules. E1: money, the one currency table, FX and cost-index observations, normalization; the scenario engine (MVP step 4): parameters, formulas, loss events and components, insurance, the customer parameter set and its API; and the scenario builder (MVP step 5): the causal graph, six banking templates, the builder and its routes |
| Code | `assurance/economics/`: the pure core in `engine/` (E1: `money.py`, `fx.py`, `cost_index.py`, `normalization.py`, `snapshot.py`; scenarios: `parameters.py`, `formulas.py`, `loss.py`, `parameter_set.py`; the builder: `templates.py`), the Django records in `models.py`, the snapshot loader in `snapshots.py`, the parameter-set routes in `api.py`, the scenario builder in `builder.py` and its routes in `scenario_api.py` |
| Migrations | `assurance/migrations/0060_economic_exposure_foundations.py` (E0), `0061_fx_and_cost_index_observations.py` (E1), `0062_scenario_parameters_and_loss_events.py` (scenarios), `0063_causal_graph_and_scenario_builds.py` (the builder) |
| Tests | `tests/test_economics_engine.py`, `tests/test_economics_money.py`, `tests/test_economics_scenarios.py`, `tests/test_economics_known_answers.py` and `tests/test_economics_templates.py` (no database), `tests/test_economics_records.py`, `tests/test_economics_scenario_records.py` and `tests/test_economics_builder.py` |
| mythos-core | `104fdc9` or later: `mythos_core.currency` (Mythos-Core#49) |
| Data in these phases | committed fixture snapshots only, SYNTHETIC TEST DATA in E1 (section 13); no live feed |

The package is a subpackage of the installed `assurance` app, not an app of its
own: its models are registered by one import line in `assurance/models.py` and
migrate with the rest of `assurance`. The pure core imports no Django, and of
mythos-core only its currency table; a test imports it in a fresh interpreter
with Django and every other part of mythos-core poisoned.

Out of scope, and added by later steps: running the distributions and the
sampler of section 23 for a scenario (step 7b); every endpoint but the customer
parameter set's and the scenario builder's; feeds and their adapters; source disagreement; building
or verifying the signed Financial Exposure Receipt (`mythos_core.exposure_receipt`,
pinned since E1 but not yet called).

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
   reads an `unreviewed` source (section 7).
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
simulation result.
The scenario step adds one route module (section 19), the only writer of a
customer parameter set and its parameters; the builder step adds another (section
23), the only writer of a built scenario, its parameters, events, components,
effects, finding links and build record. The permitted writers below are the
ones the later steps may add, and, for the observations, the snapshot loader an
operator runs; any other writer is a defect.

| Model | Holds | Permitted writers |
|---|---|---|
| `FinancialSource` | one version of one source: `source_key`, `version` (assigned on save), provider, dataset, URL, license class, trust tier, retrieval time, snapshot hash, schema version; `deployment` empty for a platform-wide source, set for one customer's own | the fixture-snapshot loader an operator runs (MVP), and later the feed adapters, each after its licensing review; an admin may record a reviewed license class as a new version |
| `ModelInventoryEntry` | one model release: model id, version, `revision` (assigned on save), owner, intended use, limitations, retirement date | an admin, as the model-risk owner; never the engine |
| `FinancialScenario` | a scenario's identity and authorship: deployment, title, system fingerprint, causal effect, the scenario it supersedes, its author | the scenario builder, and an admin or analyst of the deployment |
| `ScenarioReview` | one review of one scenario version: reviewer, verdict (`approved` or `returned`), note | an admin or analyst who authored no version of the scenario |
| `SensitiveOverride` | a request to override a parameter or value: subject, reason, requester | an admin or analyst |
| `OverrideApproval` | one approval of one override: approver | an admin, other than the requester; one approval per person |
| `FXObservation` (E1) | one exchange rate read from a source version's snapshot: base, quote, rate (`Decimal`), rate type, provider, `observed_at`, effective date, the source snapshot hash; linked to its `FinancialSource` | `assurance/economics/snapshots.py` `register_snapshot`, run by an operator on a committed snapshot; later a feed adapter, after its licensing review |
| `CostIndexObservation` (E1) | one published value of one cost-index series: series id, geography, category, base (`2020-03=100`), period, value (`Decimal`), vintage date; linked to its `FinancialSource` | the same |
| `CustomerParameterSet` (scenarios) | one version of one deployment's customer parameter set: `set_key`, `version` (assigned on save), the excluded insurance families, `variable_count`, `content_digest`, its author | the parameter-set API (section 19): an admin or analyst of the deployment, the roles that author a scenario; a viewer reads, never writes |
| `FinancialParameter` (scenarios) | one parameter: name, unit, `source_type`, low, base and high (decimal strings), currency, evidence reference, effective date, `fresh_until`, and the distribution it states, if any (section 25.1); linked to exactly one scenario or one parameter-set version | a set version's parameters: the parameter-set API, with their version and only then; a scenario's: the scenario builder (section 24) |
| `LossEvent` (scenarios) | one causal loss event of a scenario: key, currency, SPINE effect, business process, trigger, correlation group | the scenario builder (section 24), through its build route |
| `LossComponent` (scenarios) | one component of one event: family, formula id and version, as-of date, the parameters it cites by input; its status and amounts are computed on save | the same |
| `ScenarioBuild` (builder) | how one scenario version was built: its parameter-set version, currency, as-of date, versions, canonical inputs and their digest, unique per deployment | the scenario builder only |
| `CausalEffect` (builder) | one effect of a built scenario version, in exactly one of its loss events (section 24.1) | the same |
| `EffectFinding` (builder) | one finding enabling one effect, and its role | the same |
| `SimulationResult` (simulation) | one Monte Carlo run of one scenario version: seed, draws, canonical inputs and their digest, every version, the record and its digest, or the refusal's code; the timing (section 25.6) | the simulation service only (section 25.7) |

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
from a snapshot's own flag) and never another deployment's. `SensitiveOverride.check_in_force()` raises unless two
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
  23.11, and the builder's section 24.9.
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
refuse every `unverified` source, synthetic or not, is the owner's decision; this
version does not.

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
                      "effective_date": "2026-07-01", "fresh_until": "2027-06-30"}},
 "insurance_sublimits": {"notification": {"unit": "money", "currency": "USD", "low": "150000", "...": "..."}},
 "insurance_exclusions": ["regulatory_compliance"]}
```

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
holds for every entry.

A version's identity is its `content_digest`: `sha256:` and the SHA-256 of its
canonical JSON (sorted keys, the one decimal spelling, `schema` included), the
same whether read from the request or back from the stored rows.

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
  versions, which reads no amount, still answers.
- **A race**: two versions posted at the same moment that would take one number
  are refused by the unique constraint: the later is 409 and writes nothing.
- **Not on a stop path**: both routes are in `safety.stops.NOT_STOPS`; the POST
  writes nothing the decision reads.

## 20. The scenario records

`assurance/economics/models.py`, migration `0062_scenario_parameters_and_loss_events.py`.
All four are append-only like every economics record (section 6), go with their
deployment, and are checked on save with the engine's codes.

- **`CustomerParameterSet`**: `set_key` names a set within its deployment
  (`bank_prod_2026q4`, as the owner's specification's scenario request names
  one); `version` counts from 1 per deployment and key; the highest is current.
  `CustomerParameterSet.record` writes a version and its parameters in one
  transaction, refused whole or written whole. `variable_count` and
  `content_digest` are taken from the validated document before any row is
  written; a parameter added to a recorded version afterwards is
  `parameter_set_sealed`, and `intact()` re-reads the rows and compares their
  count and digest.
- **`FinancialParameter`**: exactly one parent, a scenario or a parameter-set
  version (`parent_required`, and the check constraint
  `ck_econ_parameter_one_parent`); one name per parent (`duplicate_id`, and a
  unique constraint); a set version's parameter is one of the schema's variables
  with its unit. Its values are decimal strings in the one spelling (section 12.6),
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
  step; `FinancialParameter` has no distribution type yet.
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
- **Freshness is flagged, not graded.** A stale parameter is named on the
  component that read it; no confidence grade is computed from it yet.
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

- **Nothing is served,** and no receipt is built or signed (step 6 serves; step 8
  signs).
- **No confidence grade is computed.** Expert parameters are listed, not yet
  downgraded; nor is a sensitivity analysis or a Validity Card made (step 8).
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
| `CausalEffect` | one effect of one scenario version: its key, origin (`observed` or `hypothetical`), type, the asset it is bound to (a node, by uuid) and the business process; for an observed effect, the SPINE row's uuid (`observed_effect`), the digest its signature covers (`observation`), the effect as the receipt names it (`spine_effect`: workflow and tool) and when it was observed; the template it is assigned to and every template that covers it; whether it leads its event; and the ONE `LossEvent` it is in |
| `EffectFinding` | one finding enabling one effect, as a `prerequisite`, an `amplifier` or an `alternate_path` (Finding ENABLES Effect) |
| `ScenarioBuild` | how one scenario version was built: the parameter-set version it read, the currency and as-of date, the builder, grouping and pack versions, the canonical inputs, and their content digest, unique per deployment |

The linkage is finding to effect (`EffectFinding`), effect to loss event
(`CausalEffect.loss_event`), and loss event to its components, which cite the
parameters they read (#146). An effect's attributes are the scenario's financial
parameters, named `<effect key>.<attribute>`, each with its `source_type` and
evidence. A finding, an asset and an observed effect are named by uuid, never copied
(section 8), and resolved in the scenario's own deployment when the scenario is built.

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
  caller's.
- `hypothetical`: declared by an analyst, it rests on at least one finding that
  enables it (`effect_without_finding`), and none of its attributes is
  `MYTHOS_OBSERVED`: nothing was observed (`observed_source_on_hypothetical`).

Each effect has a type and a business process from the pack's vocabularies, and
states the attributes the templates read, each in the parameter-set document's form
(unit, low, base, high, currency for money, `source_type`, `evidence_ref`,
`effective_date`, optionally `fresh_until`), so every rule of a parameter (section
14) holds for it.

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

| Attribute | Unit | Meaning |
|---|---|---|
| `success_rate` | `ratio` | the share of attempts that produced the effect, as tested |
| `exploitable_window_hours` | `hours` | how long the condition stays exploitable before detection |
| `incident_response_cost` | `money` | incident response, as a range its evidence gives |
| `legal_response_cost` | `money` | legal and regulatory response, as one range its evidence gives |
| `affected_customers` | `count` | customers the effect reaches |
| `contact_rate` | `ratio` | the share of affected customers who contact support |
| `handling_hours` | `hours` | average handling time per contact |
| `forensics_fixed_cost` | `money` | the fixed part of forensics or investigation |
| `investigation_hours` | `hours` | hours of forensics or investigation |
| `counsel_hours` | `hours` | hours of external counsel |
| `regulatory_response_cost` | `money` | regulatory response, as scenario bounds its evidence grounds (never a predicted penalty) |
| `churn_rate` | `ratio` | the extra share of affected customers who leave, from the customer's own data |
| `margin_per_customer_per_year` | `money_per_unit` | recurring margin per customer per year |
| `churn_recovery_years` | `years` | years until lost margin is won back |
| `market_capitalisation` | `money` | the company's market capitalisation (public-company analysis) |
| `share_price_decline` | `ratio` | the share-price decline attributed to the effect |
| `restitution_per_customer` | `money_per_unit` | the amount owed to each affected customer |
| `missed_cases` | `count` | fraud or AML cases the workflow missed |
| `loss_per_missed_case` | `money_per_unit` | the fraud loss per missed case |
| `rework_cost` | `money` | reworking and reprocessing the cases, as a range |
| `repeat_count` | `count` | how many times the unauthorized effect repeats |
| `loss_per_event` | `money_per_unit` | the amount one unauthorized effect moves or loses, as observed |
| `recovery_fixed_cost` | `money` | the fixed part of restoring the control or the service |
| `recovery_hours` | `hours` | engineering hours to restore the control or the service |
| `outage_hours` | `hours` | how long the provider is unavailable |
| `sla_credit_per_hour` | `money_per_hour` | SLA credits owed to customers per hour of outage |
| `sla_credit_cap` | `money` | the contracts' cap on those credits |

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
- the size of one unauthorized effect is the effect's own (observed where the effect is observed); the repeat count is how often it recurs before the approval control is restored
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

### 24.5 The grouping key

`mythos.economics.grouping/v1` (`builder.GROUPING_VERSION`). The members of a build
are its finding links and the effects no finding enables (an observed effect rests on
its observation). Each member's key is the template its effect is assigned to (id and
version), the effect's type, its asset and its business process: the grouping key
never names a finding, so every finding that enables one effect has that effect's key
and a finding never makes an event of its own. Within one key:

- observed effects are ordered by when they occurred; an event's window opens at its
  first and runs 24 hours (`builder.GROUPING_WINDOW`); an effect within the window
  joins that event, and the first after it opens another;
- an effect with no time (a hypothetical one) cannot be placed in a window and is
  never counted as an occurrence of its own: it joins the key's first event, or, where
  the key has no observed effect, the hypothetical effects make one event together.

An event's key is `ev-` and 24 hex digits of the SHA-256 of the grouping version, the
key and the instant its window opens (`undated` for an event of hypothetical effects),
so a finding added later leaves it unchanged. The event's LEAD is its first effect:
the components read the lead's attributes, once, whatever other effects and findings
the event has.

### 24.6 Idempotency

A build's identity is the content digest (`sha256:` and the SHA-256 of the canonical
JSON) of everything it is built from (`builder.build_document`): the builder
(`mythos.economics.scenario-builder/v1`, `builder.BUILDER_VERSION`), grouping and pack
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
- any changed input -- an attribute's value or source, a finding or its role, the
  parameter-set version -- is a different digest and a new scenario
  (`test_the_digest_changes_with_every_input`).

A finding found later, which enables an effect already built, is a new build of the
inputs with it (superseding the earlier scenario, `supersedes`): its event has the
same key and the same components, with the finding beside the others, and the same
totals (`test_a_late_finding_joins_its_event_and_adds_no_component`).

### 24.7 The double-count invariant

Enforced in code and in the database, not by convention:

| Invariant | Holds by | Proven by |
|---|---|---|
| findings never multiply a loss | the grouping key names no finding; components are made per event, from its lead | `test_one_two_and_five_findings_on_one_effect_make_one_event_with_the_same_totals`, `test_findings_never_make_events_of_their_own` |
| one effect is in exactly one loss event of its scenario version | `CausalEffect.loss_event` is one foreign key, not null; an effect key, and a SPINE observation, are unique within a scenario (`uq_econ_effect_key`, `uq_econ_effect_observation`), checked on save (`duplicate_id`) and by the database | `test_the_database_holds_an_effect_to_one_event` |
| an effect two templates cover is assigned to one | `templates.select`, by precedence | `test_an_effect_two_templates_cover_is_in_one_event`, `test_an_effect_two_templates_cover_is_assigned_to_one_by_precedence` |
| two distinct effects are two events | different keys, or outside one window | `test_two_distinct_effects_make_two_events` |
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
| `GET deployments/<uuid>/economics/scenarios/<scenario uuid>/events/` | `deployment-economics-scenario-events` | the scenario's events, each with its template, grouping key, effects (the lead first) and the findings enabling them, its components with their formula and, for every input, the template's source and the parameter read (the set's variable, with its version, or the effect's attribute), the gross cash loss, the loss net of the set's insurance where the set states a policy, and the market-value line apart; and the scenario's totals |

The body:

```json
{"title": "Payment agent: destination changed after approval",
 "parameter_set": {"set_key": "bank_prod_2026q4", "version": 1},
 "currency": "USD", "as_of": "2026-10-06",
 "effects": [{"key": "redirect", "origin": "observed", "observed_effect": "<the SPINE row's uuid>",
              "effect_type": "funds_transfer_altered", "asset": "<asset uuid>", "business_process": "payments",
              "attributes": {"success_rate": {"unit": "ratio", "low": "0.35", "base": "0.35", "high": "0.35",
                                              "source_type": "MYTHOS_OBSERVED", "evidence_ref": "7 of 20 attempts",
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
| `observed_effect_not_found` | the observed effect is not one of this deployment's SPINE observed effects |
| `observed_effect_not_in_force` | the SPINE observed effect does not stand: its signature does not verify now, it is not signed by an observed-effect key, or its evidence is not the document its signature names |
| `finding_not_found` | the finding is not one of this deployment's findings |
| `asset_not_found` | the asset is not one of this deployment's assets |
| `parameter_set_not_found` | the customer parameter-set version is not one of this deployment's |
| `scenario_not_found` | the scenario superseded is not one of this deployment's |

### 24.9 Limitations, and decisions for the owner

- **An event reads its lead's attributes.** Effects that join one event (two
  observations in one window) may state different attributes; the components read
  the lead's, once. The others are recorded, and shown beside it, but not merged into
  a wider range.
- **The window is a fixed 24 hours from the event's first observation.** Observations
  of one effect type on one asset and process further apart are separate events, so a
  test campaign spread over two days builds two; declaring one observed effect, with
  the tested success rate as its attribute, avoids that.
- **Hypothetical effects have no time**: within one key they make one event, or join
  the key's first observed event.
- **A rebuild by another person returns the first author's draft.** The digest is the
  inputs', not the author's; that person did not author it and may review it.
- **Nothing is normalized here.** Every money parameter a build reads is in its
  currency already (`currency_mismatch` otherwise); FX and the cost index (section 12)
  are a later step's.
- **The window, the precedence and the attribute vocabulary are this version's**; a
  change to any is a new grouping, pack or template version.
- **Not modelled**: loan or underwriting agent error and model drift, the other two
  banking families; a system fingerprint on the built scenario; claims and authority
  edges as graph nodes (they are read, not linked); controls and mitigations
  (section 21 of the owner's specification, a later step).

Decisions this version takes, which the owner may change:

1. The six templates are the six families above; loan/underwriting error and model
   drift are left for a later pack version.
2. The grouping window is 24 hours from an event's first observed effect, and an
   effect with no time joins its key's first event.
3. The precedence is the order above, so an approval bypass on payments is a payment
   loss and on fraud/AML a workflow failure.
4. An observed effect counts only while its signature verifies now; one that does not
   is refused, never built as observed.
5. Customer figures dominate: transactions per day, the average transfer, recovery,
   labour rates and the notification costs come from the parameter set, never from
   the effect; what the parameter set does not hold (a window, a lump-sum range, an
   affected population) comes from the effect's declared attributes, each with its
   source.

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

`mythos.economics.parameter-distribution/v1` (`scenario_simulation.RULE_VERSION`),
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
   severity distribution or an expert range at or above zero. The row is checked when
   it is written, with the engine's code (`EngineRefused`), and stored in the one
   spelling.
2. **A point mass** where it states none and its low, base and high are one figure.
   A point mass draws nothing.
3. **PERT(low, base, high)**, weight 4, where it states none, its values are a range,
   and its `source_type` is `EXPERT_ESTIMATE`: the only source step 7a's rule lets an
   expert range stand for without a sparse mark (section 23.1). It is listed among the
   run's expert parameters.
4. **Otherwise refused**, `no_admissible_distribution`, naming the parameter, its range
   and its source: a customer's, a benchmark's, an observed or a calculated range never
   becomes a PERT silently. Its distribution must be stated.

A scenario's frequency (section 25.5) is the exception: it must state a count
distribution (`frequency_distribution_missing`, `frequency_not_a_count`); nothing
defaults, since a PERT is not a count.

### 25.2 What is shared and what varies

`mythos.economics.variation/v1`. Section 23.11 left open how uncertainty about what a
parameter IS is separated from variation between events; this step separates them:

- **Shared**, drawn once per simulated year and the same for every occurrence of that
  year: the customer parameter set's variables (transactions per day, rates, unit
  costs), the insurance policy's terms, and the frequency. A wide range here moves
  whole years together.
- **Per occurrence**, drawn afresh for each occurrence: an effect's attributes (the
  window, the affected population, a lump-sum range), what each occurrence costs or
  reaches.

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
result is the same on every IEEE-754 platform.

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
computed once, by its Decimal formula, and that value, as the nearest binary64, is the
same in every draw (`evaluated_by: decimal_constant`). So a run whose parameters are
all point masses reproduces step 4 exactly: for each of step 4's known-answer fixtures
and the six templates, each parameter collapsed to the value step 4 reads at low, base
or high (a decreasing input's high at the low), the run's P10, P50, P90, mean and
severe-but-plausible are step 4's figure, to the last digit, with a standard error of
zero (`test_degenerate_distributions_reproduce_step_4_exactly`, 24 cases).

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
only in summary (`test_components_sum_to_their_event_and_events_to_the_scenario_per_draw`).
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

A scenario has a frequency where it holds a parameter named `frequency` (unit `count`,
events a year) stating a count distribution. Then a draw is a simulated year of N
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
| `versions` | every version the figures rest on: the wiring, the rule, the variation, the twins and their tolerance, each formula, each catalogue distribution, the sampler, the bit generator, the stream domains, numpy |
| `record`, `summaries`, `result_digest` | the whole record (schema `mythos.economics.scenario-simulation/v1`) and its digest; its scenario and event figures as decimal strings |
| `status`, `refusal_code`, `refusal_detail` | `completed`, or `refused` with the code; never both (a check constraint) |
| `started_at`, `finished_at`, `duration_ms` | the timing, outside both digests |

The canonical inputs are every event and component with its formula and the parameter
each input reads; every parameter with its values, unit, currency, source, evidence,
dates, **stated distribution** and variation; the policy's terms and exclusions; the
frequency; the severe-but-plausible percentile; the rules; and every version. They hold
neither the seed nor the draws, which are columns of their own. Nothing in a result is
a float (`result_malformed`), and both digests are recomputed on save
(`digest_mismatch`).

**Idempotent.** One row per scenario version, input digest, seed and draws
(`uq_econ_simulation_inputs`): the same inputs return the row already recorded and
never run or write a second; two runs racing past that read are stopped by the check
and by the constraint, and the later returns the first's row. A version change (numpy
included) is a new input digest, so a new row, never an old one returned. The same
seed gives the same digests, a different seed a different result digest, and two
interpreters with different `PYTHONHASHSEED` the same.

A refusal the inputs decide (no admissible distribution, no twin, a malformed stated
distribution, the values budget) is recorded, and the same inputs return it. One they
do not decide (the time budget, memory, a broken invariant, a fault, an engine that
will not import) is returned and never recorded.

### 25.7 The service

`simulation_service.simulate_scenario(scenario, *, seed, draws=100_000,
severe_percentile=95)` loads the scenario version as the scenario engine reads it: its
events in key order, each component recomputed from the rows it cites; the policy of
the parameter-set version its build names; each cited row's stated distribution; the
set's variables and terms as shared and the effects' attributes per occurrence; and
its frequency row. It looks up the result of the same identity, runs the pure engine if
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

- **Step 8**: sensitivity analysis and the most sensitive variables;
  the confidence grade (the expert parameters are listed, not yet downgraded);
  the Validity Card (the owner's specification, section 8);
  the signed receipt (the Financial Exposure Receipt).
- **No route.** Step 6 serves reports and scenario endpoints, and will call the
  service.
- **No writer states a distribution or a frequency yet.** The column and the
  frequency parameter are read and checked, but neither the parameter-set API nor the
  builder's request takes them, so a stored scenario's ranges resolve by the rule:
  point masses, expert PERTs, and a refusal for every other range. A parameter-set
  version's content digest does not cover a distribution, since none is written there.
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
2. The parameter set's variables, the policy's terms and the frequency are shared
   across a year's occurrences; an effect's attributes vary per occurrence.
3. A scenario's frequency is one parameter named `frequency`, and each occurrence
   realises every event of the scenario once.
4. Insurance is applied per event occurrence, as step 4 applies it, the limit
   included; the share of draws whose recoveries exceed the limit is reported.
5. The twins' tolerance is 1E-13 relative, against the Decimal formula at the binary64
   inputs; a component with no uncertain input is computed by its Decimal formula.
6. A refusal the inputs decide is recorded; one they do not decide is not.
7. The run's time budget is 120 s, checked between stages.
8. Every version, numpy's included, is part of the canonical inputs, so a version
   change is a new stored result, never an old one returned.
