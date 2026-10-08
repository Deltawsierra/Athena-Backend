# SPINE Economic Exposure, specification v1 (phase E0)

Economic Exposure estimates what a technical finding could cost a customer, as a
range with its confidence, sources and assumptions. It is a SPINE capability, not
a new product: a consequence layer on the same graph of evidence, claims, effects
and authority. The owner granted it a freeze exception on 7 Oct 2026 (FREEZE.md in
Mythos-Core, owner exception 9) and adopted the plan's decisions on 8 Oct 2026.

This file is the specification for phase E0, the foundations. It states the
calculation policy every later step follows, the vocabularies and the currency
table, the records and who may write them, the governance rules, and what this
version does not do. Nothing in phase E0 scores, simulates or serves anything.

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

## 1. Status and scope

| | |
|---|---|
| Phase | E0: taxonomy, source registry, model governance, currency rules |
| Code | `assurance/economics/`: the pure core in `engine/`, the Django records in `models.py` |
| Migration | `assurance/migrations/0060_economic_exposure_foundations.py` |
| Tests | `tests/test_economics_engine.py` (no database), `tests/test_economics_records.py` |
| Data in this phase | committed fixture snapshots only; no live feed |

The package is a subpackage of the installed `assurance` app, not an app of its
own: its models are registered by one import line in `assurance/models.py` and
migrate with the rest of `assurance`. The pure core imports no Django; a test
imports it in a fresh interpreter with Django poisoned.

Out of scope for E0, and added by later steps: formulas, distributions and the
simulation; the scenario builder; endpoints; feeds and their adapters; the signed
Financial Exposure Receipt (its schema is Mythos-Core's, built in parallel; this
version depends on none of it).

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
   their reviews, overrides and approvals.

Django runs both through each model's base manager, which is Django's plain
manager: the append-only refusals are not on that path, and `Meta.base_manager_name`
is never set on these models (a test pins it). Nor can a database constraint
refuse either write: a delete violates none, and a NULL account satisfies every
constraint that names an account column (the one-approval-each constraint leaves
NULL approvers out, and no check constraint names an account). The tests that pin
them are `test_removing_an_operator_is_never_held_back_by_economics_rows`, which
removes an operator named in every role through the real route and reads `204`,
and `test_the_records_go_with_their_deployment`, both in
`tests/test_economics_records.py`.

The package is off every stop path in the other direction too.
`assurance/models.py` is the only first-party module that imports
`assurance.economics`, and only to register its models;
`tests/test_economics_engine.py` fails if anything else imports it. A later step
that serves economics adds its own route module to that test, and that module is
never one the stop lane (`safety.stops`) judges. An economics failure is never a
reason to refuse anything outside economics.

## 3. Calculation policy

Every later step computes under these rules. A step that cannot follow one says
so and does not compute.

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

`assurance/economics/engine/data/iso4217.json` is a reviewed data file, read and
checked by `engine/currency.py` when it is imported. A table that breaks a rule
does not load at all. Each entry has:

| Field | Meaning |
|---|---|
| `code` | the ISO 4217 alphabetic code, three capital letters, read exactly as written (`usd` is unknown) |
| `name` | the English name the list gives |
| `minor_units` | the exponent: 0 for JPY, 2 for USD, 3 for KWD; null where ISO 4217 assigns none (precious metals, bond-market units, the SDR, XTS, XXX) |
| `status` | `active` (in List One) or `retired` (in List Three only) |
| `successor` | for a retired code, the code that replaced it (HRK to EUR); null for an active one. It says which currency replaced it, never at what rate |

The file records its own source (ISO 4217 List One and List Three, maintained by
SIX Financial Information as the ISO 4217 Maintenance Agency), how it was made,
and its review state. The E0 table was transcribed rather than generated from the
published files, because the build environment could not download them. It was
cross-checked locally against two independent derivations of the standard: the
active codes and names against Debian iso-codes 4.16.0, and every entry's minor
unit against OpenJDK 21.0.10's `java.util.Currency`, which carries the historic
codes too. They agree, except that OpenJDK lacks UYW (4 is kept) and that ROL was
corrected to OpenJDK's 0. The changes since iso-codes 4.16.0 are listed in the
file. Its review state says to verify it against the current lists before a
production run reads an entry the tests do not pin, and names the open questions.

The retired entries are the twelve currencies the euro replaced in 2002 (GRD and
PTE among them), those of every later euro adopter, and the redenominations whose
successor is one active code.

The tests pin JPY 0, USD 2, KWD 3, the retired HRK, GRD and PTE with their
successor EUR, and the SHA-256 of the whole document's canonical JSON: the entries
and the `source` and `review` records, since what the file says about where its
entries came from and how far they are checked is reviewed data as well. Any edit
to the file therefore changes the test in the same reviewed change.

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

No route, command or signal writes or reads any of these in phase E0. The
permitted writers below are the ones the later steps may add; any other writer is
a defect.

| Model | Holds | Permitted writers |
|---|---|---|
| `FinancialSource` | one version of one source: `source_key`, `version` (assigned on save), provider, dataset, URL, license class, trust tier, retrieval time, snapshot hash, schema version; `deployment` empty for a platform-wide source, set for one customer's own | the fixture-snapshot loader an operator runs (MVP), and later the feed adapters, each after its licensing review; an admin may record a reviewed license class as a new version |
| `ModelInventoryEntry` | one model release: model id, version, `revision` (assigned on save), owner, intended use, limitations, retirement date | an admin, as the model-risk owner; never the engine |
| `FinancialScenario` | a scenario's identity and authorship: deployment, title, system fingerprint, causal effect, the scenario it supersedes, its author | the scenario builder, and an admin or analyst of the deployment |
| `ScenarioReview` | one review of one scenario version: reviewer, verdict (`approved` or `returned`), note | an admin or analyst who authored no version of the scenario |
| `SensitiveOverride` | a request to override a parameter or value: subject, reason, requester | an admin or analyst |
| `OverrideApproval` | one approval of one override: approver | an admin, other than the requester; one approval per person |

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

- **No scoring.** Phase E0 computes no cost, range or grade. The vocabularies and
  records exist so that the steps that do compute share one set of codes.
- **Fixture data only.** Every source in the MVP is a committed snapshot. Nothing
  fetches a feed, and nothing is current beyond its retrieval time.
- **The currency table is transcribed.** It has not yet been diffed against the
  published List One and List Three (section 5), and holds a selection of retired
  codes, not all of List Three. It carries no exchange rates and no redenomination
  factors.
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
