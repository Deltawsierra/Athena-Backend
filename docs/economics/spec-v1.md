# SPINE Economic Exposure, specification v1 (phases E0 and E1)

Economic Exposure estimates what a technical finding could cost a customer, as a
range with its confidence, sources and assumptions. It is a SPINE capability, not
a new product: a consequence layer on the same graph of evidence, claims, effects
and authority. The owner granted it a freeze exception on 7 Oct 2026 (FREEZE.md in
Mythos-Core, owner exception 9) and adopted the plan's decisions on 8 Oct 2026.

This file is the specification for phase E0, the foundations, and phase E1,
money, currency, FX and cost-index normalization. It states the calculation
policy every later step follows, the vocabularies and the currency table, the
records and who may write them, the governance rules, how an amount is held,
converted and normalized and with what provenance, the observation data, and what
this version does not do. Nothing in phases E0 and E1 scores, simulates or serves
anything.

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

## 1. Status and scope

| | |
|---|---|
| Phase | E0: taxonomy, source registry, model governance, currency rules. E1: money, the one currency table, FX and cost-index observations, normalization |
| Code | `assurance/economics/`: the pure core in `engine/` (E1: `money.py`, `fx.py`, `cost_index.py`, `normalization.py`, `snapshot.py`), the Django records in `models.py`, the snapshot loader in `snapshots.py` |
| Migrations | `assurance/migrations/0060_economic_exposure_foundations.py` (E0), `0061_fx_and_cost_index_observations.py` (E1) |
| Tests | `tests/test_economics_engine.py` and `tests/test_economics_money.py` (no database), `tests/test_economics_records.py` |
| mythos-core | `104fdc9` or later: `mythos_core.currency` (Mythos-Core#49) |
| Data in these phases | committed fixture snapshots only, SYNTHETIC TEST DATA in E1 (section 13); no live feed |

The package is a subpackage of the installed `assurance` app, not an app of its
own: its models are registered by one import line in `assurance/models.py` and
migrate with the rest of `assurance`. The pure core imports no Django, and of
mythos-core only its currency table; a test imports it in a fresh interpreter
with Django and every other part of mythos-core poisoned.

Out of scope for E0 and E1, and added by later steps: formulas, distributions and
the simulation; the scenario builder; endpoints; feeds and their adapters; source
disagreement; building or verifying the signed Financial Exposure Receipt
(`mythos_core.exposure_receipt`, pinned since E1 but not yet called).

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
   of its sources (E1).

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
(`test_a_tenants_snapshot_goes_with_its_deployment`).

The package is off every stop path in the other direction too.
`assurance/models.py` is the only first-party module that imports
`assurance.economics`, and only to register its models;
`tests/test_economics_engine.py` fails if anything else imports it. A later step
that serves economics adds its own route module to that test, and that module is
never one the stop lane (`safety.stops`) judges. An economics failure is never a
reason to refuse anything outside economics.

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
  #141's copy had. The adapter refuses to import against any other table
  (`CurrencyTableInvalid`), and `tests/test_economics_engine.py` pins the same
  value.
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

No route, command or signal writes or reads any of these in phases E0 and E1.
The permitted writers below are the ones the later steps may add, and, for the
observations, the snapshot loader an operator runs; any other writer is a defect.

| Model | Holds | Permitted writers |
|---|---|---|
| `FinancialSource` | one version of one source: `source_key`, `version` (assigned on save), provider, dataset, URL, license class, trust tier, retrieval time, snapshot hash, schema version; `deployment` empty for a platform-wide source, set for one customer's own | the fixture-snapshot loader an operator runs (MVP), and later the feed adapters, each after its licensing review; an admin may record a reviewed license class as a new version |
| `ModelInventoryEntry` | one model release: model id, version, `revision` (assigned on save), owner, intended use, limitations, retirement date | an admin, as the model-risk owner; never the engine |
| `FinancialScenario` | a scenario's identity and authorship: deployment, title, system fingerprint, causal effect, the scenario it supersedes, its author | the scenario builder, and an admin or analyst of the deployment |
| `ScenarioReview` | one review of one scenario version: reviewer, verdict (`approved` or `returned`), note | an admin or analyst who authored no version of the scenario |
| `SensitiveOverride` | a request to override a parameter or value: subject, reason, requester | an admin or analyst |
| `OverrideApproval` | one approval of one override: approver | an admin, other than the requester; one approval per person |
| `FXObservation` (E1) | one exchange rate read from a source version's snapshot: base, quote, rate (`Decimal`), rate type, provider, `observed_at`, effective date, the source snapshot hash; linked to its `FinancialSource` | `assurance/economics/snapshots.py` `register_snapshot`, run by an operator on a committed snapshot; later a feed adapter, after its licensing review |
| `CostIndexObservation` (E1) | one published value of one cost-index series: series id, geography, category, period, value (`Decimal`), vintage date; linked to its `FinancialSource` | the same |

The two observation models are checked on save by the engine's own contracts
(`fx.FXRate`, `cost_index.IndexPoint`), so a row is refused with the engine's code
(section 11.5) for everything the engine refuses: a float, NaN or Infinity, a zero
or negative rate or value, an unknown code or one with no minor unit, a pair of
one code, an unknown rate type, a naive instant, a malformed period, a vintage
before its period. An FX row is refused unless its snapshot hash is its source
version's own (`snapshot_hash_mismatch`), and either row unless its column holds
its value exactly (`value_precision`, section 13). A series stays one geography
and one category within a source (`index_series_mismatch`). The database holds a
positive rate and value, a known rate type and a pair of two codes as check
constraints, and one row per provider, pair, rate type and date (one per series,
period and vintage) as unique constraints. Neither model has an account column.

`FinancialSource.check_usable_for_production(deployment)` raises unless a production
run for that deployment may use that version: a reviewed license class, and either
platform-wide or the deployment's own. `FinancialSource.objects.usable_for_production(deployment)`
returns exactly those: the reviewed platform-wide sources and the deployment's own,
never an `unreviewed` one and never another deployment's. `SensitiveOverride.check_in_force()` raises unless two
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

- **No scoring.** Phases E0 and E1 compute no cost range or grade. E1 converts and
  normalizes a given amount; nothing yet decides what amount a scenario costs.
- **Fixture data only.** Every source in the MVP is a committed snapshot, and the
  only one committed is SYNTHETIC TEST DATA (section 13). Nothing fetches a feed,
  and nothing is current beyond its retrieval time.
- **The currency table is transcribed.** It has not yet been diffed against the
  published List One and List Three (section 5), and holds a selection of retired
  codes, not all of List Three. It carries no exchange rates and no redenomination
  factors. It is core's table now, and athena-backend reads nothing else.
- **E1's limits** are listed in section 12.7.
- **The rules sit on the records, not yet on routes.** No route exists to enforce
  role checks; the permitted writers in section 6 bind the steps that add them.
- **Append-only is an ORM guard, not a table guard.** These write past the
  refusals: the base manager (`Model._base_manager`, deliberately Django's plain
  manager so the stop's writes in section 2 pass), `django.db.models.Model.save(row)`
  called past the model's own `save`, a plain `QuerySet(model)`, raw SQL, and a
  migration. No code may use them to write an economics row: review holds that
  line, and at the database only the constraints of section 6 hold.
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
  `Money.parse("1234.56", "USD")` reads a decimal string. A multiplier is a
  `Decimal` too (`money * 1.5` is refused).
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
show as 0.00.

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
| `index_series_mismatch` | a series with two geographies or categories, or a selector naming the wrong ones |
| `period_malformed` | a period that is not `YYYY-MM` |
| `date_malformed` | a date that is a datetime or text, an instant without a time zone |
| `date_inversion` | an event after its valuation date; indexing from a later date to an earlier; an index value published before its period began |
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
| `weekend_holiday_rule` | `last_official_rate` | on a day the provider does not publish (Saturday, Sunday, or a holiday in its calendar), the last official rate: its last publication day's. `none` turns the rule off |
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
  downgrade `stale_rate`.
- **Same currency.** No conversion: the rule `same_currency`, factor 1.
- **Round trip.** Through one rate, USD to EUR and back returns the amount to
  within 1E-50, relative (`fx.ROUND_TRIP_TOLERANCE`), and exactly at display.

The rules a step records are `same_currency`, `exact`, `last_official_rate` and
`linear_interpolation`.

### 12.3 Cost indices

An index value (`cost_index.IndexPoint`, stored as `CostIndexObservation`) is one
published value of one series for one calendar month, in one vintage: series id,
geography, category, period (`YYYY-MM`), value, vintage date and snapshot hash. An
`IndexSelector` names the series, its geography and category, and the currency its
prices are in.

`cost_index.index(amount, from_date, to_date, book, selector)` multiplies an amount
by the series' value for `to_date`'s month over its value for `from_date`'s month.
An amount in another currency than the series' is refused (`currency_mismatch`).
Each month's value is the latest vintage published on or before the as-of date
(the valuation date), and the step records which. The event month's value is that
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
in EUR on 2026-10-08. 1,000 x 1.1000 = USD 1,100 at the event date's rate;
x 125.000 / 100.000 = USD 1,375 at the valuation date's prices; / 1.0500 (an
EUR/USD rate, inverted) = EUR 1,309.52.

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
 "event_date": "2020-03-02", "valuation_date": "2026-10-08",
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
                     "source_snapshot_hash": "sha256:54ff...01a5",
                     "source_key": "synthetic-fx-and-cost-index", "source_version": 1}],
   "input": {"amount": "1000", "currency": "EUR"}, "output": {"amount": "1100", "currency": "USD"}},
  {"step": "cost_index", "series_id": "SYN-CPI-US", "geography": "US", "category": "...", "currency": "USD",
   "from_date": "2020-03-02", "to_date": "2026-10-08", "from_period": "2020-03", "to_period": "2026-10",
   "period_used": "2026-10", "as_of": "2026-10-08", "rule": "exact_period", "lag_months": 0,
   "ratio": "1.25", "stale": false, "estimate": false, "downgrades": [],
   "observations": [{"series_id": "SYN-CPI-US", "period": "2020-03", "value": "100", "vintage_date": "2020-04-10",
                     "source_snapshot_hash": "sha256:54ff...01a5", "...": "..."},
                    {"series_id": "SYN-CPI-US", "period": "2026-10", "value": "125", "vintage_date": "2026-10-08",
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
`sha256:54ff61637f36e517d02bb146615e94e9867db5270355bc76eb0fd41b4b4001a5`, pinned
by `tests/test_economics_money.py` and `tests/test_economics_records.py`, and it is
registered as a `FinancialSource` (`source_key` `synthetic-fx-and-cost-index`,
platform-wide) with licence class `open` and trust tier `unverified`: the data is
Mythos's own to redistribute, and made-up numbers are never trusted above
unverified (the snapshot parser refuses a synthetic snapshot that claims more).

It holds 17 FX observations (EUR/USD, USD/JPY and USD/KWD on dates around
2020-03-02, Easter 2020 and 2026-10-08, a missing Wednesday on 2020-03-04, and the
market's rates), a calendar with SYNTHETIC-REF's two Easter holidays, and 7 index
values (`SYN-CPI-US` with a revised vintage for 2026-09, and `SYN-HICP-EA`).

The document (schema `mythos.economics.observation-snapshot/v1`, `engine/snapshot.py`)
has exactly `schema`, `label`, `synthetic`, `source`, `calendars`, `fx` and
`cost_index`. Every rate and value is a decimal string; a JSON number is refused
(`not_decimal`), because a reader that parses it as a float has already changed
it. A broken document is `snapshot_malformed`.

`snapshots.register_snapshot(path)` writes, in one transaction, the source version
and every observation, each through its model's checks; a file already registered
under its hash is returned, not written again. `snapshots.fx_book` and
`snapshots.index_book` read stored observations back into the engine, and a test
shows the normalization from the rows equals the one from the file.

Django keeps a decimal on SQLite, this service's database, as a float rounded to
15 significant digits. So every decimal column holds at most 15 digits -- a rate
up to 999,999.999999999 (9 after the point), an index value up to
999,999,999.999999 (6 after the point) -- and a value a column cannot hold
exactly is refused (`value_precision`), never rounded to fit. The engine itself
has no such limit.

**For the owner to decide.** The synthetic snapshot is licensed `open`, which is a
reviewed licence class, so `FinancialSource.objects.usable_for_production()` would
return it. Nothing runs in production in E1; before anything does, either the
production gate also refuses `unverified` sources, or synthetic sources are kept
out of production databases.
