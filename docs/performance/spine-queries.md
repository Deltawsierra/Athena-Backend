# SPINE query and traversal paths: measured, then optimized

Phase 5: *Optimize SPINE query/traversal paths*. SPINE is on the critical path of
every assessment -- claim derivation, graph traversal, decision recompute -- so its
cost gates end-to-end latency. The quality bar: claim derivation and decision
recompute improve against a measured baseline **with identical outputs**, a
golden-output test guarding correctness, and no datastore change without a profile
that justifies it.

This page is the baseline (master `a32f63a`, where this was measured), what it
showed, what changed because of it, the same measurements against master `cf14de0`
(which merged #176, scoping one of the lists the baseline found) and after, and how
to repeat them.

## Method

**The corpus.** `tests/spine_corpus.py` builds deployments through the code paths
production uses: components (agents, tools with read, write, code-execution,
egress and payment permissions, data stores, service accounts, an MCP server,
models, a gateway and a vector store behind shared providers with assertions), a
data boundary, findings with graded evidence, claims re-derived through several
versions as inputs move, retest obligations (resolved and open), latent conditions
(pending, fired and holding their claim), evidence recorded against claims,
approved workflows, signed chain outcomes, an observed effect ingested through the
signed route, and an authority chain recorded through the API. Six finding profiles
cycle by rank (a critical open; at worst high; only medium and below; every finding
closed; every finding an accepted risk -- standing, lapsed and outgrown; none), so
the deployments land on different decisions.

The clock is held, every UUID a model or the code draws is seeded, and the engine
keys are fixed, so two builds in two processes write the same rows: the golden
fixture recorded twice from master is byte-identical, and so is every measurement
below across rounds.

**The measured deployment** (`REALISTIC` in `tests/spine_measure.py`): about 36
components, 80 findings (88 for the all-accepted target), claims re-derived
through 8 versions, 40 evidence items against claims, 3 latent conditions, one
recorded chain. Two targets: `critical-open` (rank 0) and `all-accepted` (rank 4,
every finding an accepted risk -- the profile the accepted-risk read is sized by).

**The paths.**

| path | what runs |
|---|---|
| `derive_claims` | `claims.derive_claims` (steady state: the recompute-claims route's work) |
| `assess_ripple` | `ripple.assess_ripple` with the route's prefetch (the ripple traversal) |
| `recompute_decision` | `decision.recompute_decision` (the one writer of the decision) |
| refresh (backstop) | `decision.refresh_stored_decisions` -- what the after-commit backstop runs after any input write: carry, latent evaluation, route/approval/edge notes, recompute |
| refresh (another writer's decision) | the same for a decision another release left (a rollout): the claim, the watches read, the recompute that brings it current |
| `decision_support` | the published read (`current_decision`, then `decision_support`) |

**The instruments**, all in-process, deterministic except CPU:

- **statements** -- every statement a path issues (`connection.execute_wrapper`);
- **EXPLAIN QUERY PLAN** of each: a `SCAN` of a table whose rows belong to a
  deployment (with or without an index) is a read whose cost follows the whole table;
- **SQLite VM steps** -- the virtual-machine instructions the path runs, counted with
  `sqlite3.Connection.set_progress_handler` (granule 100 for a path's total, so
  totals are ±100; exact, granule 1, per statement in the tests). A row visited
  costs steps; a seek is one, so this measures the rows a path reads, independent of
  host load;
- **CPU** -- `time.process_time` of the path, 15 runs per measurement, three
  measurements per tree, base and head alternating on the same seeds. The host is
  shared (4 CPUs; load 2.5-4.6 during the a32f63a series, 1.8-2.2 during the
  cf14de0 series); `process_time` excludes waiting but not cache and frequency
  contention. The CPU column is supporting evidence; the deterministic columns are
  the result.

**Growth.** *With others*: the same target measured again after 7 more deployments
of the same shape (9 in all). *With history*: measured again after 30 re-derives
that flip the boundary's training approval and one tool's permissions back and
forth -- 60 more claim versions (24 to 84 claim rows), the current graph unchanged.

## What the baseline showed (master a32f63a)

| target | path | statements | VM steps | CPU ms (median) |
|---|---|---|---|---|
| critical-open | `derive_claims` | 50 | 26,400 | 44.9 |
| critical-open | `assess_ripple` | 7 | 8,200 | 9.1 |
| critical-open | `recompute_decision` | 56 | 28,500 | 32.5 |
| critical-open | refresh (backstop) | 84 | 39,100 | 49.4 |
| critical-open | refresh (another writer's decision) | 142 | 68,400 | 83.2 |
| critical-open | `decision_support` | 51 | 28,700 | 33.8 |
| all-accepted | `derive_claims` | 50 | 27,200 | 47.7 |
| all-accepted | `assess_ripple` | 7 | 8,500 | 8.7 |
| all-accepted | `recompute_decision` | **130** | 25,200 | 44.0 |
| all-accepted | refresh (backstop) | **158** | 36,400 | 61.3 |
| all-accepted | refresh (another writer's decision) | **290** | 62,400 | 107.3 |
| all-accepted | `decision_support` | **125** | 25,700 | 45.1 |

Growth, as `a32f63a` / `cf14de0` / head. No path's statement count grew with
other deployments on any tree; "claims" is a full scan of the claim table (every
version of every deployment) somewhere on the path. VM-step totals are ±100.

| target | path | +others: VM steps | +others: full scans | +history: VM steps |
|---|---|---|---|---|
| critical-open | `derive_claims` | -100 / -100 / -100 | none / none / none | +700 / +700 / +600 |
| critical-open | `assess_ripple` | -200 / -200 / -200 | none / none / none | +0 / +0 / +0 |
| critical-open | `recompute_decision` | +800 / -100 / -200 | claims / none / none | +3,200 / +2,500 / +1,600 |
| critical-open | refresh (backstop) | +1,000 / +100 / +400 | claims / none / none | +6,300 / +5,400 / +3,200 |
| critical-open | refresh (another writer's decision) | +2,500 / +700 / -300 | claims / claims / none | +10,500 / +8,900 / +4,900 |
| critical-open | `decision_support` | +500 / -400 / -100 | claims / none / none | +2,800 / +2,000 / +1,300 |
| all-accepted | `derive_claims` | +0 / +0 / +0 | none / none / none | +1,200 / +1,200 / +800 |
| all-accepted | `assess_ripple` | +100 / +100 / +100 | none / none / none | +200 / +200 / +200 |
| all-accepted | `recompute_decision` | +1,200 / +300 / +100 | claims / none / none | +3,700 / +2,600 / +1,600 |
| all-accepted | refresh (backstop) | +1,200 / +400 / -200 | claims / none / none | +6,900 / +5,800 / +3,300 |
| all-accepted | refresh (another writer's decision) | +3,100 / +1,400 / +400 | claims / claims / none | +12,100 / +9,900 / +5,500 |
| all-accepted | `decision_support` | +900 / +100 / -100 | claims / none / none | +3,300 / +2,300 / +1,600 |

Attributed statement by statement (`tests/spine_corpus.py: each_statement`), the
baseline showed five things, and only these were changed:

1. **Two reads that followed the whole database.** The refresh of a decision another
   writer left asks whether its watches were read
   (`decision._watches_read_since`) through `claim__in=AssuranceClaim.objects.closed()`
   and `.current()`: SQLite builds each list by scanning every claim version of every
   deployment (`LIST SUBQUERY`, `SCAN U0`). With 6 small deployments beside the
   target, those two statements went from 160 and 80 VM steps to 770 and 160 (one
   target and six other deployments of the larger probe shape). A
   third such list, in `conditions_the_decision_reads`, on every decision path, is
   #176's (merged at `cf14de0`) and is not changed here; it is the scan that
   disappears from every path but the rollout refresh between `a32f63a` and
   `cf14de0` in the table above. The database-size test below holds it too.
2. **An N+1 on accepted risks.** `accepted_risk_signal` read the deployment's accepted
   findings through the related manager with `.only(...)`, which defers
   `deployment_id`; Django reads that column to hand each row its deployment, so it
   fetched it back one query per accepted finding: 74 extra statements in one
   recompute of the all-accepted target (130 against 56), in every refresh and every
   decision-support read.
3. **The component graph read nine times per recompute.** Every reader of the graph --
   the coverage manifest (twice), the tool contracts in force, the route map,
   effective access, the authority chains' graph, the effects that need a chain --
   reads `deployment.assets.all()` and documents that its caller should prefetch;
   nothing did. The authority chains and the chain outcomes each read the asset table
   once more for the route serving now. The route map then fetched each component's
   provider one query at a time (an N+1 on provider-backed components). In one
   recompute of a default-shape corpus deployment (rank 0) the asset table alone was
   about 9,300 of 13,700 VM steps.
4. **A re-derive read the graph three times**: its plan's prefetch, then the route
   serving now twice more for the receipt it digests.
5. **Current claims found by walking their history.** `current()` is
   `valid_to IS NULL AND effective_to IS NULL`; through the deployment index alone,
   every read of a deployment's current claims -- the decision's claim signal, the
   re-derive's staleness pass, the backstop -- visited every version the deployment
   ever had (310 to 810 VM steps for one such read after 30 versions).

Measured and **not** changed, because nothing in them was slow for its inputs:

- **The ripple traversal** (`assess_ripple`): 7 statements, every one a keyed
  search, no growth with other deployments or with history. Its CPU (about 9 ms) is
  the effective-access and boundary assessments in Python.
- **`derive_claims`' per-claim reads** (the claim row, its evidence token -- read
  twice by design, once to plan and once under the lock -- its events and stored
  weighing): fixed per claim identity, and a deployment has one per deriver. About a
  third of its CPU is the full assurance receipt it builds for the digest, and most
  of the rest is ORM query compilation and row hydration (cProfile). Follow-ups, not
  done here.
- **The edge and approval history reads** (`edge_history.history`,
  `approval_history`): they read a deployment's whole history by design (a chain is
  read as of its dispatch).
- **`decision_support`** reads its parts on the caller's instance, where a prefetch
  could outlive a later write in the same request; it gains the accepted-risk fix
  only. Applying the graph read once there, on a copy of the instance (as
  `edge_history.edges_now` does), is a follow-up.

**No datastore change.** After this change (with #176) every statement of these
paths, on every table, is a keyed search; roughly a third of a path's CPU is spent
compiling and issuing SQL (cProfile of `derive_claims` on the realistic deployment:
`execute_sql` 0.200 s of 0.613 s over five runs); the rest is Python. Nothing here
points at the store.

## What changed

| # | change | where | guarded by | mutation (test goes red) |
|---|---|---|---|---|
| 1 | scope both subquery lists to the deployment | `decision._watches_read_since` | `test_no_path_does_more_work_for_other_deployments_data` | unscope: `SCAN U0` of claims |
| 2 | read `deployment` with the accepted findings | `decision.accepted_risk_signal` | `test_a_recompute_reads_its_accepted_risks_in_one_statement` | drop it from `.only()`: 11 statements, not 1 |
| 3 | read the graph once per recompute, under the row lock, only when the recompute reads inputs (never for a pause or a held decision) | `decision._read_inputs_once` | `test_a_recompute_reads_the_component_graph_once`, `test_a_pause_reads_no_component_of_the_graph` | no prefetch; or no held route |
| 4 | the route serving now computed from the graph a reading already holds -- for that instance only, never another instance of the deployment (a refresh the reading sets off reads, and notes, its own) | `served_route.route_held`, used by #3 and by the derive plan | `test_a_re_derive_reads_the_component_graph_once`, `test_a_held_route_answers_only_for_the_instance_that_holds_the_graph` (and #3's test) | no held route in the plan: 3 asset reads; held by pk instead of instance: a stale route answered to a fresh instance |
| 5 | index `(deployment, valid_to, effective_to)` | `AssuranceClaim.Meta`, migration `0080_claim_current_index` | `test_the_current_claims_are_found_without_reading_their_history` | migration without the index |

Correctness: `tests/test_spine_paths_publish_what_they_published.py` builds the
six-deployment corpus, runs derivation, the ripple traversal and the decision
recompute over every deployment (the writer, the backstop's refresh and the refresh
of another writer's decision), and compares, byte for byte with
`tests/fixtures/spine_golden.json` recorded from master `a32f63a` (recorded again
from `cf14de0`, it is byte-identical: #176 changes no output here): every claim
version, claim event, stored weighing, retest, latent condition, decision
transition and deployment decision column; the ripple assessment, the
decision-support payload and the assurance receipt; and every set of decision
inputs the recompute read (`DecisionParts`: which rows each signal holds, and each
signal). Foreign keys are published as the uuid or username of the row they name,
never as autoincrement ids. A deliberately wrong prefetch (one that hides the tools
from the recompute's readers) and a wrong held route each fail it; every
optimization above passes it unchanged, and reverting any one of them turns its own
test red (nine mutations, each caught by the tests named above). Reverting #176's
scoping on the merged head turns the database-size test red as well.

## After: master cf14de0 against the head

| target | path | statements | VM steps | CPU ms (median; min-max of 3, master / head) |
|---|---|---|---|---|
| critical-open | `derive_claims` | 50 → 48 | 26,400 → 21,100 (-20%) | 45.4 → 42.4 (-7%; 44.0-48.2 / 42.4-44.1) |
| critical-open | `assess_ripple` | 7 → 7 | 8,200 → 8,200 | 8.2 → 8.1 (-1%; 8.2-8.4 / 8.0-8.2) |
| critical-open | `recompute_decision` | 56 → 30 | 28,400 → 14,100 (-50%) | 32.2 → 19.9 (-38%; 31.6-32.9 / 19.7-20.2) |
| critical-open | refresh (backstop) | 84 → 58 | 39,100 → 24,100 (-38%) | 47.7 → 36.0 (-25%; 46.6-48.1 / 35.9-36.2) |
| critical-open | refresh (another writer's decision) | 142 → 90 | 68,300 → 38,700 (-43%) | 81.2 → 58.1 (-28%; 80.2-83.6 / 57.3-58.5) |
| critical-open | `decision_support` | 51 → 38 | 28,700 → 28,200 (-2%) | 31.9 → 29.3 (-8%; 31.9-32.5 / 29.2-29.6) |
| all-accepted | `derive_claims` | 50 → 48 | 27,200 → 21,900 (-19%) | 45.1 → 43.0 (-5%; 44.7-46.2 / 42.7-43.2) |
| all-accepted | `assess_ripple` | 7 → 7 | 8,500 → 8,500 | 8.6 → 8.3 (-3%; 8.2-8.6 / 8.3-8.4) |
| all-accepted | `recompute_decision` | 130 → 29 | 25,100 → 9,800 (-61%) | 42.7 → 18.4 (-57%; 42.4-43.6 / 18.0-18.5) |
| all-accepted | refresh (backstop) | 158 → 57 | 36,300 → 20,600 (-43%) | 58.7 → 33.7 (-43%; 58.5-59.9 / 33.7-34.3) |
| all-accepted | refresh (another writer's decision) | 290 → 88 | 62,200 → 30,500 (-51%) | 104.5 → 54.8 (-48%; 103.3-106.5 / 53.8-56.4) |
| all-accepted | `decision_support` | 125 → 37 | 25,600 → 24,300 (-5%) | 43.4 → 28.7 (-34%; 43.0-44.6 / 27.8-28.7) |

n: statements and VM steps are exact and were identical in all three rounds of
each tree; CPU is the median of three per-round medians of 15 runs each (45 runs
per cell per tree), with each tree's range of the three medians. `derive_claims`' CPU fell 5-7% here and was
within noise in the busier a32f63a series; its deterministic work fell by a fifth.

What still grows: with other deployments, nothing (the ±100 is the totals'
resolution; the database-size test holds every statement to two VM steps); with
history, only the reads that are history by design -- the closed versions the legal
carry and #176's list read, the edge history -- and the current-claims reads no
longer do.

## Repeating it

```bash
export DJANGO_SECRET_KEY=ci-secret-key-not-used-outside-ci DJANGO_DEBUG=1
# the measurements above, as JSON (about 40 s)
SPINE_MEASURE_OUT=spine.json pytest tests/spine_measure.py::test_measure
# the guards
pytest tests/test_spine_paths_publish_what_they_published.py tests/test_spine_queries_follow_their_own_deployment.py
```

`tests/spine_measure.py` is collected only when named. Its `test_record_golden`
rewrites the golden fixture: run it on the code *before* an optimization, never
after one, or the golden test compares a tree with itself.
