# Athena `assurance` app — adversarial code audit

Scope: `assurance/` Phase 0 + Phase 1 (models, ingest, assets, boundary, capability,
route, change, receipt, decision, unknowns, serializers, views, signals, urls, admin).
Method: read every file; verified load-bearing claims by executing code against the
project venv. Review only — no code was modified.

Note on scope: **`bom.py` does not exist** in the app (only a stale
`assurance/__pycache__/bom.cpython-311.pyc` remains, with no importer anywhere in
the repo). There is no BOM module to review.

## Counts by severity
- CRITICAL: 0
- HIGH: 3
- MEDIUM: 3
- LOW: 5

---

## HIGH

### H1 — `_affirmative()` naive substring negation misses real "trains-on-data" violations
`assurance/boundary.py:48-57`

`_NEGATIONS = ("no","not","never","opt","zero","false","disabled","off")` is matched as
a plain substring against the whole declared value. Common affirmative phrases contain
these substrings, so `_affirmative()` returns **False** for values that clearly assert
training on data. Verified in the venv:

```
_affirmative('Yes, opt-in training is enabled')  -> False   # "opt" ∈ "opt-in"
_affirmative('trains on data for now')           -> False   # "no" ∈ "now"
_affirmative('yes, we train on customer data')   -> True    # (only the clean cases pass)
```

Failure path (`_assess_flow`, boundary.py:108-116): when `policy.training_allowed` is
False and a `trains_on_data` assertion exists but `_affirmative()` returns False, the code
appends **neither** a violation **nor** an unknown. The flow then reads `status="approved"`
(if region also passes). So a provider that *explicitly declares it trains on customer
data*, phrased with an incidental "opt"/"now"/etc., is reported as within the approved
boundary. This is exactly the "never let a forbidden thing read as a pass" invariant being
broken, on the flagship differentiator, in the dangerous direction (false negative).

Minimal fix: match tokens, not substrings — normalise/split on non-alphanumerics and test
against a negation *token* set (and match affirmations as tokens too), e.g.
`tokens = re.split(r"[^a-z0-9]+", v); if tokens & NEG: return False`. Or invert: only treat
as affirmative on an explicit allow-list of tokens (`yes/true/trains/shares/enabled`) with
no negation token present.

### H2 — Approved boundary rule `third_party_sharing_allowed` is never enforced
`assurance/boundary.py:85-130` (+ model field `DataBoundary.third_party_sharing_allowed`,
assertion field `ProviderAssertion.Field.SUBPROCESSORS`)

`_assess_flow` reconciles only `region` and `trains_on_data`. `policy.third_party_sharing_allowed`
is collected into `_policy_dict` (boundary.py:184-193) and surfaced by the API, but it is
**never compared against anything** — the provider's `subprocessors` assertion is not read,
and no violation/unknown is ever produced for sharing. A deployment whose boundary says
"third-party sharing NOT approved" against a provider that declares subprocessors/sharing
gets `status="approved"` (when region/training pass). A declared rule is silently dropped
and the summary counts omit the sharing axis entirely — overstating confidence.

Failure scenario: boundary `{training_allowed: True, third_party_sharing_allowed: False}`,
provider assertion `subprocessors = "AWS, OpenAI, Datadog"` → expected a violation (or at
least an unknown "sharing posture not declared"); actual output `approved`.

Minimal fix: add a sharing branch mirroring the training one: when
`not policy.third_party_sharing_allowed`, read the `subprocessors` (and/or a sharing)
assertion; absent → unknown; affirmative/non-empty → violation.

### H3 — N+1 on the main findings list: `asset` and `owner` are not select_related
`assurance/views.py:192-205` (`FindingViewSet.get_queryset`), with
`assurance/serializers.py:67-69, 69` (`asset_uuid`/`asset_name`/`owner`)

`get_queryset` does `.select_related("deployment").prefetch_related("evidence")` only.
`FindingSerializer` then reads:
- `asset_uuid` / `asset_name` via `source="asset.*"` → `obj.asset` is an un-cached FK →
  **one query per finding** (ingest attaches an asset to essentially every finding, so this
  fires for nearly all rows);
- `owner` (`SlugRelatedField`) → `obj.owner` un-cached FK → **one more query per finding**
  that has an owner.

So the list endpoint issues ~2N extra queries for N findings. `evidence` is correctly
prefetched (used by the `evidence` field, the `evidence_class` property, and `receipt`), so
that path is clean — the gap is only `asset`/`owner`.

Minimal fix: `.select_related("deployment", "asset", "owner")` in `FindingViewSet.get_queryset`.

---

## MEDIUM

### M1 — `recompute` endpoint silently clears a PAUSED failsafe decision
`assurance/views.py:86-95`

`recompute` reads `paused = bool(request.data.get("paused", False))` and calls
`recompute_decision(deployment, paused=paused)` unconditionally. The ingest path is careful
to *never* clear a pause (`ingest.py:333` — `if deployment.decision != PAUSED:`), but this
endpoint has no such guard: an admin POSTing `recompute` with no body on a deployment whose
decision is currently `PAUSED` recomputes from findings and overwrites the pause. There is
no server-side persistent "is paused" source of truth (grep shows nothing in `failsafe/`
sets `Deployment.decision`), so the pause lives only in the decision field — which this call
bypasses. Inconsistent with the stated invariant "an automated re-ingest must not silently
clear a human's stop."

Minimal fix: in `recompute`, default `paused` to the current state, i.e.
`paused = bool(request.data.get("paused", deployment.decision == Deployment.Decision.PAUSED))`,
or refuse to recompute a PAUSED deployment unless an explicit `paused=false` unpause flag is
sent.

### M2 — `_region_allowed` two-way substring match yields false approvals
`assurance/boundary.py:60-72`

The match is `r in d or d in r` on lower-cased strings. Verified:
`_region_allowed('aus-east', ['us']) -> True` — an Australian region reads as approved
because "us" is a substring of "aus-east". Documented as "loose by design / errs toward not
flagging," but this errs toward *approving an out-of-boundary region*, which is the wrong
direction for a boundary check and can hide a genuine region violation.

Minimal fix: require prefix/segment matching, e.g. `d == r or d.startswith(r + "-")`
(so `eu`→`eu-west-1` still matches but `us`↛`aus-east`).

### M3 — N+1 on `owner` in the Unknowns list
`assurance/views.py:318-337` (`UnknownViewSet.get_queryset`) + `serializers.py:288`

`get_queryset` does `.select_related("deployment", "finding")` but the `owner`
`SlugRelatedField` reads `obj.owner` (un-cached FK) → one query per unknown that has an
owner. Fix: add `"owner"` to `select_related`.

---

## LOW

### L1 — Machine asset classification is create-only, so a host that leaves scope stays "known"
`assurance/assets.py:63-100, 251-259`

`_get_or_refresh` sets `classification` only on create (to preserve human reclassification).
But it makes the *machine's own* initial classification permanent too: if a first scan saw a
host in-scope (`KNOWN`) and the engagement scope later changes so the host is out of scope,
a re-derive computes `UNMANAGED` but never applies it — the asset keeps reading as managed
(`KNOWN`), so it is never surfaced as a shadow destination. Partial erosion of the
shadow-asset honesty guarantee across scope changes. Consider storing machine-vs-human
provenance and letting a re-derive downgrade a machine-set classification while still never
touching a human-set one.

### L2 — Non-privileged "latest scan boundary" is computed over only-visible findings
`assurance/views.py:168-190`

`latest_seen_by_deployment(self._scoped_findings())` for a non-privileged user aggregates
`Max(last_seen)` over just the findings that user can see (`scan__user=user | deployment__owner=user`).
If they can see only a subset of a deployment's findings, the computed "latest scan" can be
behind the true latest, mislabeling `change_status` (e.g. a current finding shown as
`cleared`, or a stale one as `recurring`). Acceptable scoping trade-off, but worth noting as
an accuracy caveat.

### L3 — DataBoundary PUT is not a true full replace
`assurance/views.py:107-129` + `serializers.py:319-337`

`DataBoundarySerializer(data=request.data)` (non-partial) maps model booleans to
`required=False`. On PUT, an omitted `training_allowed` / `third_party_sharing_allowed` is
absent from `validated_data`, so `update_or_create(defaults=...)` leaves the *existing* value
in place rather than resetting to the model default. A caller intending to turn a permission
off by omission silently keeps it on — mildly at odds with the "silence is not consent"
posture. Consider requiring the booleans on PUT, or documenting PATCH semantics.

### L4 — Ingest-time asset reconciliation is O(findings) queries
`assurance/assets.py:304-324`

`derive_assets` step 4 iterates `deployment.findings.all()` and issues a `get_or_create`
(+ possible `finding.save`) per finding. This runs on the (backgrounded, on-commit) ingest
path rather than a read endpoint, so it is far less hot than H3/M3, but it scales linearly in
writes per scan. Could batch the endpoint-asset creation and use `bulk_update` for the
`finding.asset` assignment.

### L5 — Leftover artifact / missing module
`assurance/__pycache__/bom.cpython-311.pyc`

A compiled `bom` module remains with no `bom.py` source and no importer in the repo. Stale
build artifact — harmless but should be cleaned (and the roadmap/brief reference to `bom.py`
is out of date). No BOM code exists to review.

---

## Clean bill — checked and found solid

- **Evidence-class ordering / weakest-evidence.** `evidence_strength()` maps strongest→0,
  and *unrecognised* classes to `len(order)` (weakest), so a bad label never reads as strong.
  `Finding.evidence_class` (`max(..., key=evidence_strength)`) correctly returns the weakest
  attached class and falls back to `UNKNOWN` when none. `ProviderSerializer.get_profile`
  likewise reports the weakest. Consistent everywhere.
- **decision.py.** Precedence is worst-first and correct; `None` for an unassessed
  deployment (guarded on `.exists()` over *all* findings, not the active set); PAUSED override;
  active set excludes closed/accepted/false-positive; evidence prefetched (no N+1). The
  `f.evidence_class in _UNVERIFIED` check across a set of enum members works — verified in the
  venv that Django `TextChoices` hash equals the value's hash, so `'unknown' in {EvidenceClass.UNKNOWN,…}`
  is True. Not a bug.
- **Receipt determinism.** Canonical JSON (`sort_keys`, compact separators), evidence rows
  sorted, deployment digests sorted (Merkle-style), timestamp kept *outside* the hash. Same DB
  state ⇒ same digest. `content_hash` in ingest also uses `sort_keys`. Deterministic.
- **Idempotent dedup / non-destructive merge.** Fingerprints are stable
  (`sha256(deployment.pk|basis)`, `signature_id` preferred, else type+descriptor); re-ingest
  refreshes engine-owned fields via `update_fields` and never touches human status/owner;
  Evidence is `update_or_create` keyed on `(finding, source)`; unknowns re-derive preserves
  human disposition and re-opens only machine-resolved gaps (`auto_resolved`).
- **capability.py invariant.** `_MANAGED = {APPROVED, KNOWN}`; a capability with only
  unmanaged/unknown/high-risk sources is `shadow=True` and its risk is raised one band
  (`_RISK_RAISED`), never hidden. `_max_risk` and the sorts are correct (most-concerning first).
  Prefetch `assets` covers it (metadata is a JSONField, no query).
- **route.py.** Shadow nodes flagged (`UNMANAGED`), unresolved agent→tool references surfaced
  rather than dropped, empty logs layer reported as a finding, declared vs inferred edges kept
  distinct, edge dedup + no self-edges. Prefetch `assets__provider` covers node/provider reads.
- **boundary.py invariant (region/training axes).** With no policy, every flow gets an
  "no boundary approved" unknown → `status` is `unknown`, never `approved`; an undeclared
  posture is an unknown, not a pass. (The gaps are H1/H2/M2, not this core invariant.)
  Prefetch `assets__provider__assertions` keeps it query-light.
- **Query-filter hardening.** `_valid_uuid` guards every `?deployment=`/`?provider=` filter
  (malformed ⇒ `.none()`, not a 500); `severity`/`status`/`kind`/`classification`/`impact`/
  `field` filters are CharField equality (bad value ⇒ empty set, no 500).
- **Permission gating.** Reads open to authenticated users; all mutations
  (create/update/destroy/`recompute`/`data_boundary` PUT) go through `_require_admin`;
  `http_method_names` restrict verbs (findings/unknowns are GET+PATCH only). `is_admin`/
  `is_analyst` exist as user-model properties, so `_is_privileged`/`_is_admin` resolve as
  intended (and default-False `getattr` fails safe).
- **Defensive parsing.** `_cvss_score`, `confidence`, and `_finding_severity` all normalise/
  swallow bad input so a malformed engine field cannot 500 the whole ingest; unrecognised
  severities fall to `info` within `SEVERITY_ORDER`.
- **No mutable-default / aliasing bugs.** Model JSON defaults use callables (`dict`/`list`);
  no `def f(x=[])`; per-key accumulator lists/dicts (boundary `by_provider`, capability
  `sources`, route nodes) are freshly constructed, not shared.
- **signals.py.** `transaction.on_commit`, exception-swallowed (never fatal to scan
  completion), idempotent, gated by `ASSURANCE_INGEST_ON_COMPLETE` and by the
  `status`-in-`update_fields` completion check.
