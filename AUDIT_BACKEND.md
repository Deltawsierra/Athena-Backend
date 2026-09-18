# Athena `assurance` app — adversarial code audit

Date: 2026-09-18. Scope: the `assurance/` app as it stands on `master` plus the
branch that regenerated this file — models, ingest/signals, the assessment layer
(boundary, capability, compliance, business_impact, vendor, roi, operational,
operational_risk, route, ripple), the SPINE layer (receipt, fingerprint, policy,
claims, invalidation, revalidation, decision, bom, bom_drift, change), connectors,
serializers, views, urls, admin. Method: read every file; verified load-bearing
claims by executing code against the project venv (`tests/settings_test.py`).
Review of the current tree — the earlier audit had gone stale and is corrected
below.

## What the previous audit got wrong (now corrected)

The prior version of this file was written against an older tree and is no longer
accurate. Every one of its open findings has since been fixed, and its central
scope note was already false:

- **"`bom.py` does not exist" — false.** `assurance/bom.py` is a full Phase 1.7
  AI-BOM module, and there is an entire Stage-3 BOM/drift subsystem around it
  (`bom_drift.py`, `DeclaredComponent`, migration `0011`, `tests/test_assurance_bom.py`,
  `tests/test_spine_bom_drift.py`). The BOM digest is bound into the assurance
  receipt (`receipt._assessment_digests`).
- **H1 (`_affirmative` substring negation) — fixed.** `boundary.py` now matches
  negations and affirmations as whole-word **tokens** (`_WORD_RE`, `_negated`,
  `_affirmative`), with explicit opt-in/opt-out phrase handling. "trains on data
  for now" and "yes, opt-in training is enabled" both read as violations
  (regression-tested).
- **H2 (`third_party_sharing_allowed` never enforced) — fixed.** `_assess_flow`
  has a sharing branch: absent subprocessors posture → unknown, a real sharing
  declaration → violation.
- **H3 (N+1 on the findings list) — fixed.** `FindingViewSet.get_queryset` is
  `.select_related("deployment", "asset", "owner", "assignee").prefetch_related("evidence")`.
- **M1 (recompute clears a PAUSED failsafe) — fixed.** `recompute` defaults
  `paused` to the deployment's current paused state (`_parse_paused`), so a bare
  recompute never lifts a pause.
- **M2 (`_region_allowed` two-way substring) — fixed.** Region matching is exact
  or delimited-subregion (`d == r or d.startswith(f"{r}-"/f"{r}_")`); `aus-east`
  is no longer approved under an `["us"]` boundary.
- **M3 (N+1 on `owner` in the Unknowns list) — fixed.** `UnknownViewSet` now
  `select_related("deployment", "finding", "owner")`.
- **L5 (leftover `bom.cpython-311.pyc` / missing module) — moot.** `bom.py` exists.

Fixed findings are **not** carried forward as if open.

## Counts by severity (current tree)

- CRITICAL: 0
- HIGH: 0
- MEDIUM: 0
- LOW: 4 (all honestly-scoped trade-offs, documented in-code)
- Observations / follow-ups: 2

No correctness, robustness, or honesty defect in the assurance layer rises above
LOW at this reading. The SPINE honesty invariants hold (see the clean bill).

---

## LOW

### L1 — Machine asset classification is create-only; a host leaving scope stays "known"
`assurance/assets.py` (`_get_or_refresh`)

`classification` (and `name`) are set only on create, to preserve a human's
reclassification across re-derives. A side effect: the *machine's own* first
classification is also permanent. If a first scan saw a host in scope (`KNOWN`)
and the engagement scope later narrows so the host is out of scope, a re-derive
computes `UNMANAGED` but never applies it — the asset keeps reading as managed and
is never surfaced as a shadow destination. This is a real but bounded erosion of
the shadow-asset guarantee across scope changes; the fix is provenance
(machine-vs-human) so a re-derive may downgrade a machine-set classification while
never touching a human-set one. Deliberately unchanged here — it needs a schema
field and a migration, so it is a scoped follow-up, not a drive-by edit.

### L2 — Non-privileged "latest scan" boundary is computed over only-visible findings
`assurance/views.py` (`FindingViewSet._scoped_findings` / `get_serializer_context`)

The change-intelligence boundary (`latest_seen_by_deployment`) is correctly
computed over the *unfiltered* set (a `?status=open` view cannot redefine "latest
scan") — but for a non-privileged user that set is still only the findings they
may see (`scan__user=user | deployment__owner=user`). If they can see a subset of a
deployment's findings, the computed "latest scan" can trail the true latest,
mislabeling `change_status`. An inherent scoping trade-off, honest and documented
in-code; noted as an accuracy caveat, not a defect.

### L3 — `DataBoundary` PUT is not a true full replace
`assurance/views.py` (`data_boundary`) + `assurance/serializers.py` (`DataBoundarySerializer`)

`DataBoundarySerializer` is a `ModelSerializer` whose boolean fields default on the
model, so they are `required=False`. On PUT, `update_or_create(defaults=…)` with an
omitted `training_allowed` / `third_party_sharing_allowed` leaves the *existing*
value in place rather than resetting to the model default. A caller intending to
turn a permission off by omission silently keeps it on — mildly at odds with
"silence is not consent". Left unchanged deliberately: forcing the booleans on PUT,
or documenting PATCH semantics, is an API-contract decision, not a safe drive-by.
Listed as a follow-up below.

### L4 — Ingest-time asset reconciliation is O(findings) queries
`assurance/assets.py` (`derive_assets`, the finding→endpoint-asset step)

`derive_assets` iterates `deployment.findings.all()` and issues a `get_or_create`
(+ possible `finding.save`) per finding. This runs on the backgrounded, on-commit
ingest path (not a read endpoint), so it is far cooler than a list endpoint, but it
scales linearly in writes per scan. Could batch the endpoint-asset creation and
`bulk_update` the `finding.asset` assignment. Performance only; correctness is fine.

---

## Observations / documented follow-ups

### O1 — `subprocessors` "N/A"/"unknown" text reads as sharing, not as an unknown
`assurance/boundary.py` (`_shares_with_third_parties`)

The sharing heuristic now suppresses both negations ("none", "no subprocessors")
and positive internal-only declarations ("internal only", "in-house",
"first-party", "self-hosted") via a conservative whole-word/allow-list guard, while
still flagging any value that names a vendor or affirms sharing (regression-tested,
both directions). One residual edge remains: a value that is neither a negation nor
a recognized internal-only phrase but expresses *ignorance* — a literal `"n/a"`,
`"tbd"`, `"unknown"` — is read as sharing rather than surfaced as an undeclared
posture (an unknown). This is the *safe* direction (it over-flags rather than
hiding a real sharing declaration) and is rare, so it was left as a documented
edge rather than widening the allow-list into ambiguous "ignorance" tokens. A
future refinement could route recognized ignorance markers to the unknown branch.

### O2 — `DataBoundary` PUT contract (see L3)

Decide whether PUT must carry the booleans (a true replace) or is documented as
PATCH-style merge, then enforce it in the serializer. Deferred because it changes
the write contract clients depend on.

---

## Clean bill — checked and found solid

- **Boundary honesty (all axes).** With no policy, every flow is `unknown`, never
  `approved`; an undeclared posture is an unknown, not a pass, and distinct from a
  violation. Region matching is prefix/segment (no accidental substring); training
  and sharing are whole-word/token reasoning; the new internal-only guard is
  conservative (an internal-only reading requires a positive indicator **and** an
  all-benign token set, so a named vendor keeps the sharing reading). Prefetch
  `assets__provider__assertions` keeps it query-light.
- **Business-impact honesty + owner attribution.** Bands are ordinal, never a
  dollar figure; resolved findings carry no active band. Owner attribution is
  grounded in the real `Finding.owner` FK — a finding with no owner rolls up to an
  explicit `(unassigned)` bucket, never guessed onto a person; per-*process*
  attribution is still not invented (no process field). Deterministic (same DB
  state ⇒ identical map).
- **Per-deployment policy pinning (new).** `policy.policy_pin` is a deterministic,
  timestamp-free pin derived from the *live* governing constants (readiness order,
  severity thresholds, resolved/unverified sets, claim caps, evidence TTL), so a
  rules change moves it even without a version bump. It is stored on each claim,
  compared in `derive_claims` (a policy change supersedes/rebinds a claim) and in
  `invalidation.check_invalidations` (a policy change invalidates a decision and
  opens an attributed retest, off a pass to STALE), and surfaced on
  `decision_support` and in the assurance receipt (standard bumped to
  `…/1.1`). It never fabricates a pass and never softens a CONTRADICTED claim.
- **Receipt / fingerprint determinism.** Canonical JSON (sorted keys, compact
  separators), evidence rows and finding digests sorted (Merkle-style), every
  timestamp kept *outside* the hash. Same DB state ⇒ same digest and same system
  fingerprint; the fingerprint excludes timestamps/uuids/counters, so mere passage
  of time never moves it. The declared architecture (BOM drift) is deliberately
  kept out of the system fingerprint.
- **Claim invariants (SPINE).** `confidence` is `None`, never `0.0`, when UNKNOWN;
  vendor-asserted claims cap at SUPPORTED and cannot be hand-verified; a claim is
  as strong as its weakest evidence; every lifecycle move is an attributed
  `ClaimEvent`; a human REVOKED claim is never invalidated, marked, or superseded.
  Bitemporal versioning supersedes rather than rewrites.
- **Decision precedence.** Worst-first; `None` for a genuinely unassessed
  deployment (guarded on `.exists()` over *all* findings); PAUSED overrides; the
  claim cap can only hold a decision back, never improve it; active set excludes
  closed/accepted/false-positive; evidence prefetched (no N+1).
- **Connector honesty (dispatch deliberately NOT built).** An unconfigured
  connector is inert: `push_finding` short-circuits before any transport touch and
  returns `ok=False, "<name> not configured"`; the base config is
  never-configured, so a connector with no override cannot look ready. Live
  automated dispatch / posture fetching is an explicit deferred follow-up, absent
  by design.
- **Idempotent, non-destructive ingest.** Stable fingerprints (`signature_id`
  preferred, else type+descriptor); re-ingest refreshes engine-owned fields and
  never clobbers human `status`/`owner`; the on-commit signal is exception-swallowed
  (never fatal to scan completion), gated by `ASSURANCE_INGEST_ON_COMPLETE` and the
  `status`-in-`update_fields` completion check. **Phase 0.1b (ingestion wired to
  scan completion) is complete** — model + `ingest` + `signals` + `tests/
  test_assurance_ingest_signal.py`, no migration drift; the `apps.py` reference is
  accurate provenance, not an open to-do.
- **Query-filter hardening & permissions.** `_valid_uuid` guards every UUID filter
  (malformed ⇒ `.none()`, not a 500); reads are open to authenticated users, all
  mutations go through `_require_admin`; `http_method_names` restrict verbs;
  findings/unknowns are GET+PATCH only, and the remediation workflow moves only
  through attributed, state-machine-checked actions (never a raw field write).
- **No mutable-default / aliasing bugs.** Model JSON defaults use callables
  (`dict`/`list`); per-key accumulators (dimensions, owners, capability sources,
  route nodes, boundary `by_provider`) are freshly constructed.
