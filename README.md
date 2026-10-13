# Mythos platform

Django REST backend and React frontend for the Mythos security platform. It
drives a separate scanning engine over HTTP.

## Running it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt      # enough to run and test the backend
cp .env.example .env                     # then fill in DJANGO_SECRET_KEY
export $(grep -v '^#' .env | xargs)
python manage.py migrate
python manage.py runserver
```

In a second terminal:

```bash
npm install
npm run dev                              # http://localhost:3000, proxying to :8000
```

`requirements.txt` is the full runtime set. It pulls torch, transformers, spaCy
and datasets, none of which this repository imports, plus a model wheel served
from a GitHub URL, so it will not install behind a proxy or in an air-gapped
build. `requirements-dev.txt` is what the tests and CI actually need.

## The engine

The backend calls the engine with an operator key and enforces its decisions in
`audit/middleware.py`. Set `CYBERENGINE_URL` and `CYBERENGINE_OPERATOR_KEY`.
Without a key the gateway allows every request and says so in the log.

`DEFENDER_MONITOR_ONLY` defaults to on: block and throttle decisions are logged
but not enforced. Turning enforcement on is a deliberate go-live step.

The engine client (`ai_engine/services/cyberengine_client.py`) bounds every answer
it parses. An answer longer than 8 MiB is not parsed at all. Every other answer is
checked for nesting depth in one linear pass before it is parsed: an answer cut off
inside a string used to take seconds to reject, and blocked every other thread of
the worker while it did. An answer that fails either check is reported as
unreadable. A scan or retest answer may name no run in its body while the engine's
`X-Run-Id` header names one. The run is then kept under the header's id. A scan is
collected by that id and, while it cannot be collected, stays pending under it. A
retest whose answer names no end state reads as running, stoppable by that id.

A stop is never sent to the engine and never refused by it, in either mode, and
no throttle refuses or counts one. The stops are listed in `safety/stops.py`:
a pause (`{"paused": true}`; a lift is start-direction and is not a stop), a
claim revoked or contradicted, a failsafe pause, stand-down or terminate drafted
(not a resume or release), a signature on a pause, stand-down or terminate (not
on a resume or release), a resume or release cancelled (cancelling a pause,
stand-down or terminate withdraws a stop, so it is not one), the three
stop-lane reads (the failsafe state, the command list, and a command's detail),
the engines' poll with its token, a deployment's automated dispatch switched
off, an engagement's authority withdrawn (moved off running, scope emptied, or
window closed -- deleting an engagement destroys its record and is not a stop),
a scan's Stop (`POST /api/pentest/scans/<uuid>/stop/`, below), and an operator
demoted (never promoted) or removed. A token refresh whose
refresh token verifies, for an account that exists and is active, and has not
been spent is exempt the same way; a refresh spends its token exactly once,
however many refreshes of it arrive together (`safety/refresh.py`), so a used
one is judged like any other bad token.
A stop is recognised only in its canonical form: JSON or a URL-encoded form in
UTF-8 or ASCII, at most 64 KiB, carrying only the stop's own fields and an
optional `note` or `reason`. Anything else on those routes is not a stop. So the
engine no longer sees stops, including stops that will fail authentication.
Every other request waits for the engine at most `DEFENDER_TIMEOUT_SECONDS` in
all, and is allowed without a decision after that. A hostile engine can hold
all `DEFENDER_MAX_IN_FLIGHT` call slots; every other request then waits out its
deadline and is allowed, and stops are unaffected.

### The failsafe service token

A stop client should not need a password sign-in to stop: sign-in is not a
stop, so the gateway judges it and failed guesses can lock it. Set
`FAILSAFE_SERVICE_TOKEN` (at least 32 characters, e.g. `openssl rand -hex 32`;
shorter is treated as unset) and `FAILSAFE_SERVICE_USER` (the username of the
active admin or analyst account the client acts as). A request that presents
the token in the `X-Failsafe-Service-Token` header is authenticated as that
account, before any other credential is looked at, but ONLY when the request is
a stop or a stop-lane read, and not on the account routes. Anywhere else -- a
lift, a resume or release draft or signature, a cancel of a pause, stand-down
or terminate, an engagement deleted, an operator demoted or removed, any other
read or write, the engines' poll, a refresh -- the header is ignored, and so is
a token that does not match: the request is judged and authenticated exactly as
if the header were absent. What the token reads is limited to the pause,
stand-down and terminate commands in flight, their signing bytes and the
engine's live state. A stolen token can stop things; it cannot start anything,
withdraw a stop, destroy a record or remove an operator. The token is compared
as HMAC-SHA256 digests in constant time, and only a match costs a database
read; a read of the service account that fails is answered 503 with its reason
(never 401, which would send a client back to its password). The
athena-dashboard server will present it on its stops in a follow-up; until then
it signs in with its service account's password as before, so until then its
stops still depend on that sign-in.

### Sign-in and the stop lane

Password sign-ins are limited per address and username
(`DJANGO_THROTTLE_SIGN_IN`, default 10/min), where the username is the one
authentication looks up (trimmed as SimpleJWT trims it, NFKC-normalised and
case-folded, so every spelling of one account shares one budget), and per
address across every username (`DJANGO_THROTTLE_SIGN_IN_ADDRESS`, default
60/min). Each attempt is counted before its password is hashed, by an atomic
increment of a row in the database (the `safety` app's one table), so a burst
of simultaneous attempts, and every worker process, count against one number;
past either limit the attempt is answered 429 without a hash (and, once the
window is full, without a write). Only attempts
that fail stay counted: a successful sign-in gives its attempt back and clears
its own address-and-username count. If the count cannot be written, the
sign-in is answered 503 and nothing is hashed. `manage.py check --deploy` warns
(`safety.W001`) if that database exists only inside one process (an in-memory
SQLite database). A sign-in from an address under a guessing flood can be
refused, the operator's own included if they share the attacker's address.

A stop draft is never refused and never throttled. Drafted again by the same
account while its identical draft (same engine, same action, same reason) is
unsigned and has at least half its window (`FAILSAFE_COMMAND_TTL_SECONDS`, 600 s)
left, it returns that draft (200: the same uuid, the same bytes to sign, and the
window it has left, at least 300 s) instead of adding one; with another reason
it is a new draft. Identical drafts sent at once are one row. A reason is at
most 1,000 characters: a longer one is answered 400 naming the limit. One
account has at most `FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT` (default 100)
unsigned stop drafts awaiting a signature: a draft past that is made, and the
account's OLDEST unsigned stop drafts are superseded (status `superseded`, with
an audit event naming the draft that superseded each; no longer signable; drafted
again, a new draft). Never another account's, and never one already carrying a
signature -- but the dashboard's service account is one account, so every
dashboard user's drafts share its limit. Every draft still adds a row to the
command history, as every stop adds to the audit trail. The command list and the
state view list the stop commands awaiting a signature first -- those already
signed once, then each account's drafts in turn, so a flood from one account lies
behind every other operator's newest -- at most 500, never cut by the other row
caps. Every stop-lane read does work bounded by its row limits, whatever the
number of commands, returns at most `FAILSAFE_STOP_LANE_READ_BYTES` (default
1,000,000) of commands in that order, says in its `X-Failsafe-More` header (and
the state view in `more`) whether it left any out, and marks at most 200
commands expired per read, in one write. Identical stop-lane reads by one
account at once -- identical in the parameters the view reads, whatever else the
query string carries -- share one computation; reads of different engines do
not. The state view waits for the engine's live state
`FAILSAFE_STATE_ENGINE_SECONDS` (default 2) at most, and reads at most 64 KiB of
the engine's answer; a longer answer reads as not reported. Two operators signing
one command at once both count: each signature is added to the command as it is at
that moment, under the write lock.

Removing an operator (`DELETE /api/accounts/users/<id>/`) is a stop. The
engagements they created are kept, with the creator unlinked; such an engagement
is visible to admins only. A contradiction they made on an assurance claim stays
in force, and stays theirs. Each claim event records, when it is written, that a
person made it and the name their account had (`by_person`, `actor_username`,
migration `assurance.0047`). So removing the account no longer turns their stop
into the machine's reading for the next re-derive to lift. `0047` fills both
fields for the events of every account that still exists. An account removed
before `0047` has no name left to copy, and its events read as the machine's.
Rolling back past `0047` drops the snapshot.

## Signed chain outcomes

`POST /api/assurance/deployments/<uuid>/chain-outcomes/observed/` records chain
outcomes an engine signed, verified against the keyring named by
`ASSURANCE_OUTCOME_KEYRING`. "Observed" in that path means reported by an engine
at an instant. It does not mean anyone saw the effect. Every row and composition
these routes publish says what kind of evidence it is (`evidence_kind`,
`evidence_census`), and the kind follows from who signed it:

- `authorization_check`: signed by Achilles. The action gate authorized, or
  refused, the workflow's action at dispatch. A held shows the authority chain
  resolves. It does not show the effect happened.
- `scan`: signed by Athena. Its checks ran against the target.
- `observed_effect`: signed by Achilles' observed-effect key (observer
  `achilles-effect`, a key that signs nothing else): the dispatch that carried a
  permitted action out saw its provider complete it. Recorded only with its
  `mythos.observed-effect` evidence document (v1, v2 or v3), through
  `POST /api/assurance/deployments/<uuid>/observed-effects/` and the observed-effect
  service's credential (`assurance/observed_effects.py`); it proves an authority
  chain's `produces` hop when the document names that chain's tool and gate decision.
  A v3 document also carries the workflow approval the gate read in force itself,
  which `under_policy` reads as gate-attested.
- `unclassified`: signed by a trusted key for an engine not listed above.
- `attested`: typed in by an operator, or signed by a key the keyring no longer
  trusts.
- `unknown`: typed in without saying what it rests on.

The Action Gate reads the approval in force itself (authority chain short 3):
`GET /api/assurance/deployments/<uuid>/workflows/<slug>/approval-in-force/` with
`X-Gate-Approval-Token` (`ASSURANCE_GATE_APPROVAL_TOKEN` / `_USER`, a credential of
its own: one that is also the observed-effect, sign-in collector, grant collector or
closure-evidence service's token, or the failsafe's `FAILSAFE_SERVICE_TOKEN` or
`FAILSAFE_POLL_TOKEN`, is treated as unset) answers the approval
version's id and digest (`200`), `404` for none in force, or `409` while its history
is not level with it (`assurance/gate_approval.py`). It reads only.

Two more signers sign records that are not chain outcomes, each on its own route
with its own service credential (`assurance/identity_evidence.py`), and each proving
one hop of an authority chain that starts at a person:

- `authentication`: signed by the sign-in collector (observer
  `mythos-signin-collector`) with a `mythos.authentication/v1` document -- a person
  signed in as a principal, at an instant, through an identity provider. Posted to
  `POST /api/assurance/deployments/<uuid>/authentications/` with
  `X-Authentication-Evidence-Token` (`ASSURANCE_AUTHENTICATION_EVIDENCE_TOKEN` /
  `_USER`). It proves `authenticated_as` when the sign-in falls inside the chain's
  window: at most a day before the effect, not after it, in a session still open.
- `delegation`: signed by the grant collector (observer `mythos-grant-collector`)
  with a `mythos.delegation/v1` document -- a principal delegated an agent a scope
  for a window, and whether the grant is revoked. Posted to
  `POST /api/assurance/deployments/<uuid>/delegations/` with
  `X-Delegation-Evidence-Token` (`ASSURANCE_DELEGATION_EVIDENCE_TOKEN` / `_USER`). It
  proves `delegates_to` when the scope covers the chain's action and the window holds
  the effect, and the grant was not revoked before the effect. A revocation is never
  refused for its age or order.

Both collectors are Mythos-run today (`witness: mythos`, the owner's 5 Oct scope
call); a customer-run or third-party collector is planned.

A held Achilles signed still counts as demonstrated: the composition's own rule
reads `ready`. What the chains contribute to the deployment decision is less.
Where an approved workflow holds on an authorization check alone, or on a `held`
signed by an engine this platform has not classified, they contribute
`ready_restricted` at best (`CHAIN_CAPS` in `assurance/workflow_chains.py`, an
owner default, #278). One such workflow is enough, whatever the others show. A
`held` signed by Athena is not capped.

## Claim confidence

Every assurance claim the API serves (`/api/assurance/claims/`, and each
deployment's `assurance-claims/`) carries a `confidence` and, beside it, a
`confidence_basis`. The confidence is not a probability that the claim is true.
It is the ordinal strength of the weakest class of evidence supporting the claim,
as mythos-core's evidence-class table gives it
(`mythos_core.evidence.strength_from_evidence_class`, Mythos-Core#31). mythos-core
keeps that table once for the whole platform, and only the order of its values
means anything.
This service used to compute the number with a formula of its own,
`max(0.1, 1.0 - 0.12 * rank)`. The table has the same values, so no derived
claim's number changed.

The confidence follows the claim's status, whoever set it:

- `supported`, `partially_verified` or `verified`: the table's strength for the
  claim's evidence class.
- `unknown`, `contradicted`, `stale`, `revoked` or `draft`: none (`null`), never
  `0`.

A person who moves a claim gets the confidence of the status they set, and a
re-derive that keeps their status keeps it. Moving a derived `contradicted` claim
back to `supported` gives it the strength of its evidence class. Moving a claim to
`unknown` takes the confidence away. Before this, both moves kept the deriver's
confidence for the deriver's status. A stale mark (expired evidence, drift, a
declared condition that fired) and an evidence hold carry none. When a hold is
released, the claim lands on its reading with that reading's confidence. A
superseded version keeps what it carried when it was closed.

`confidence_basis` says what the number is. With a number, it gives mythos-core's
basis line, the evidence class and the table. With no number, it starts `none: `
and says why. The evidence audit served with a claim says the same of the
confidence of the reading under a hold (`base_confidence`, beside
`base_confidence_basis`).

Migration `assurance.0048` recomputes the stored confidence of every claim still
believed, and the base confidence under every evidence hold. It leaves superseded
versions as they were closed. Rolling it back does nothing.

The rank a finding's weakest evidence is taken by
(`assurance.models.evidence_strength`) and the qualitative reading of a class
(Observed, Inferred, Hypothesized, Unknown) come from the same table. The
assurance policy pins the table's order of the classes, so a change to that order
moves the policy pin. The order is the one this service kept before, so the pin
did not move.

## Retest-gated closure

A finding with `retest_required` set owes a retest before it can be called fixed.
Ingest sets the flag on every medium-or-worse finding. Such a finding moves to
`status=closed`, or to `remediation_state=resolved`, only on a retest record
(`RetestClosureEvidence`, migration `assurance.0049`) that shows the check run
against four classes of fixture:

| Class | What it is | The check must |
| --- | --- | --- |
| `vulnerable` | the original defect | fail |
| `repaired` | the fix | pass |
| `benign` | a case that never had the defect | pass |
| `incomplete_repair` | a fixture that looks repaired but leaves the effect reachable | still fail, on each of six patterns |

The six incomplete-repair patterns are each their own fixture:

- `restored_reachability`: the path reopens some other way.
- `changed_defaults`: the fix works but flips a default users depend on.
- `lost_compensating_control`: the patch removes a workaround without replacing it.
- `displaced_effects`: the behaviour moves to an adjacent code path.
- `restored_persistence`: state that should have been purged survives.
- `operational_breakage`: the fix is correct but breaks something unrelated.

An incomplete repair that passed means the check was fooled. A cosmetic
error-message change, a disabled logger or a partial endpoint check would have
read as a repair, so the check's pass on the real fix proves nothing either.

The gate is `assurance.retest_closure.enforce`, called from `Finding.save`. Every
writer goes through it: the findings PATCH, the Django admin, the
`remediation/transition` action and `remediation.apply_transition`. It reads the
finding's latest record and refuses the move when:

- there is no record;
- the record's origin is not `independent` (the only origin that carries weight,
  as for claim evidence);
- the record names no artifact digest;
- the record is older than the finding's `last_seen`, so a scan saw the defect
  after the retest ran;
- any class or pattern is missing, not run, unreadable, or has the wrong outcome.

The refusal names every class and pattern that failed. The finding stays where it
was. The PATCH and the transition answer 400 with the reasons, and the admin
shows them on the form. The admin cannot untick `retest_required`, because the
flag belongs to ingest.

These are not closures and are not gated: `accepted`, `false_positive`,
`invalidated`, a finding with no retest owed, and a save that does not move the
finding into `closed` or `resolved`. bom drift's own close of a drift finding is
also not gated, because drift findings never carry `retest_required`. Nothing
here touches a stop, a claim revoke or a pause.

A record is written with `retest_closure.record_closure_evidence`, whose one API
route is the engine service's `POST /api/assurance/findings/<uuid>/closure-evidence/`
(`assurance/closure_evidence.py`). Neither the deployment decision nor the
Assurance Receipt changed. A refused close leaves the finding unresolved, and the
decision reads it the same way it did before.

### The repair contract comes first

Before a fix is worked on, an operator agrees the finding's repair contract
(`RepairContract`, migration `assurance.0052`, `assurance/repair_contract.py`):

- `prohibited_effect`: the unauthorized effect the repair must eliminate;
- `preserved_behaviours`: the legitimate behaviours that must keep working, each
  named once.

`POST /api/assurance/findings/<uuid>/repair-contracts/` agrees the next version
(admin only, attributed to the caller); `GET` on the same route lists every version
to any operator who can see the finding. A contract is never edited or deleted: a
change is a new version, and the latest is current. Its `content_digest` is
`sha256:` over the canonical JSON of `{finding_ref, version, prohibited_effect,
preserved_behaviours}`. The admin shows contracts read-only.

**No fix before agreement.** A finding's `remediation_state` cannot move into
`in_progress`, `in_review` or `resolved` without a current contract, and a finding
cannot be created already in one of those states. The gate is
`remediation.enforce_contract`, called from `Finding.save` and `Finding.clean`, so
the `remediation/transition` action, `remediation.apply_transition`, the admin and
any other save all go through it; the refusal names what is missing. A finding that
was already in one of those states is not rewritten: it stays there, can still be
moved to `wont_fix`, needs a contract for any further working move, and its closure
is held to the contract like any other.

**Closure is held to the contract.** On top of every rule above, a retest-gated
close is refused unless the latest record's replay document carries a `contract`
block:

```json
{"digest": "sha256:<hex>", "preserved": {"<behaviour name>": "retained"}}
```

that names the digest of the finding's current contract, reads `retained` for
every behaviour that contract preserves, and names none it does not. A contract
superseded after the replay leaves that replay unable to close. A behaviour read
`broken` or `unknown`, one left out, or one the contract never named, is refused by
name. **A producer must now send `contract`.** A document without it is still
recorded, as before, and closes nothing. The block is strictly typed (an unknown
field is refused by name) and sits inside the document's canonical digest, which
Minotaur-Backend's `POST /remediation-outcomes` computes byte-identically for the
same document: it accepts and stores the block too.

**Sent on to Minotaur's dataset, under Blue's own key.** Each recorded document is
forwarded to Minotaur-Backend's `POST /remediation-outcomes` after its record commits
(`assurance/closure_forward.py`; retried by `manage.py retry_closure_forwards`). It is
off unless `MINOTAUR_OUTCOMES_URL` and a credential are set. The credential is
`MINOTAUR_OUTCOMES_KEY`: a key of Minotaur-Backend's `outcome-recorder` role, Blue's,
which records remediation outcomes and cannot drive a campaign, post a release
decision, import a run or abort one. It is read from the Django setting of that name,
or from the environment when the settings name none.

- **Legacy:** `MINOTAUR_RUNNER_KEY`, a Minotaur-Backend `runner` key, is still sent
  when it is the only credential set, so an unmoved deployment keeps forwarding. That
  key spans campaign driving, outcome recording, release decisions, run imports and
  aborts, so role separation is not in force. `manage.py check` warns
  (`assurance.W304`), each process logs it once at start, and the retry command
  prints which credential it sends under.
- **Refused:** the same secret set as both is one credential for two roles. It is
  never sent, and forwarding is off until they differ: logged as an error at start,
  and a warning in `manage.py check` (`assurance.W305`). Never a check error, which
  would refuse every command that runs the checks, the scheduled Stop delivery
  (`deliver_owed_stops`) among them. No credential setting ever fails a record, a
  command or the start.

## Economic Exposure: the customer parameter set

Economic Exposure estimates what a finding could cost, as a range with its sources
(`assurance/economics/`, specified in `docs/economics/spec-v1.md`). The scenario
engine computes a deterministic low, base and high per loss component from
parameters that each carry their unit, `source_type` and evidence (sections 14 to
18), and a service simulates a stored scenario (below). One route module serves the
customer's own figures,
a deployment-scoped, versioned parameter set (section 19):

- `GET /api/assurance/deployments/<uuid>/economics/parameter-sets/<set_key>/`: the
  current version;
- `GET .../parameter-sets/<set_key>/versions/`: every version, newest first;
- `POST .../parameter-sets/<set_key>/versions/`: the next version, append-only,
  from a document of the schema's thirty variables, each with its unit; an admin
  or analyst only, attributed to the caller. Each entry may state the distribution
  it draws from in a simulation, and the document the scenario's frequency (events
  a year, with its count distribution): each is held to its own low, base and high
  before anything is written (from both sides, a count on any other row included;
  the frequency, whose figures are values of its rate, by the rate its count
  implies, a fixed rate only as a Poisson of it), and a contradiction is refused
  naming the variable and the test it failed (section 19.4). A build re-checks the
  distributions of the version it names, under the rule then in force.

A deployment the caller cannot see is 404. The body is strict JSON of at most 64
KiB (413 otherwise): an unknown field, a JSON number where a decimal string
belongs, and a key twice in one object are refused with the engine's code. None of
these routes is a stop, and `assurance/urls.py` imports their module guarded: if it
fails to import, its routes are logged and not served, and every stop and the
system checks load without them. While economics cannot read mythos-core's
currency table, the write answers 503; nothing at import reads the table. A version
that states a distribution is 503 too while the probabilistic engine (numpy) will
not import; one that states none never imports it. Every check runs before the
version's transaction, which only inserts.

### Raising a source's trust tier

A production run refuses a source still trusted as `unverified`. An admin raises a
source's tier (spec, section 6.1), from the same module:

- `GET /api/assurance/economics/sources/<uuid>/trust-raises/`: every raise of the
  source that version belongs to, newest first;
- `POST .../sources/<uuid>/trust-raises/` with `{"to_tier", "reason"}`: below
  `authoritative`, a new version of the source at that tier, recorded at once (every
  field as before but the tier, recorded by the admin); `authoritative` is recorded
  pending, with no version;
- `POST /api/assurance/economics/trust-raises/<uuid>/approve/`: a pending raise
  approved by an admin OTHER than the one who asked, while that admin is still one;
  it records the version. This route is the only approver;
- `POST .../trust-raises/<uuid>/withdraw/`: a pending raise withdrawn by any admin,
  who is named on the record.

A pending raise expires 30 days after its request, by the service's clock: an
approval after that is refused (`trust_raise_expired`) and the request moves to
`expired`; a withdrawal after that is refused as not pending; a read shows it expired
without writing.

Only upward, and only from the latest version of the source. Anyone but an admin is
403 (anonymous 401); a tenant's source is 404 to whoever cannot see that deployment.
Every raise is one append-only record of who asked, who approved or withdrew, why,
when and through which channel (`api` or `command`), and the names outlive a removed
account. Nothing else records an `authoritative` version: not a plain save and not
the snapshot loader, which refuses a file stating it. A raised version reads the FX
and cost-index rows its snapshot was registered with, and its provenance names both
versions. A write that meets a busy database is 503 with Retry-After, and writes
nothing.

`manage.py raise_source_trust request|withdraw ... --as <admin>` is the same rules and
the same record for the operator: it asks for the `--as` account's password at the
terminal (never from its arguments or the environment) and authenticates it, and it
never approves. None of these is a stop.

### The scenario builder

A second route module, imported guarded in a guard of its own, builds a scenario's
causal loss events from SPINE effects (signed observed effects, or hypothetical
ones an analyst declares) and the findings that enable them, through six banking
templates (section 24):

- `POST /api/assurance/deployments/<uuid>/economics/scenarios/build/`: a scenario
  draft from the effects, findings and parameter-set version the body names; an
  admin or analyst only, the draft authored by the caller. An effect's attribute may
  state its distribution, held to its figures as a parameter set's is. The same
  inputs return the scenario already built (200), never a second; a build raced by
  the same build is 409 and writes nothing. The draft records the deployment's SPINE
  system fingerprint as it is when it is built, or none and why where it cannot be
  computed (never a failed build); a rebuild returns the draft with the fingerprint
  it recorded;
- `GET .../economics/scenarios/<scenario uuid>/events/`: its system fingerprint, its
  review status and its events, each with its effects, findings, components and
  where every input came from. It follows the report's Unknown banner rule: with no
  verified grade A to D on the version's latest stored result (none yet, refused, no
  card, rows that do not verify, or graded Unknown) it carries `banner: "Unknown: not
  for capital decisions"`, `excluded_from_totals: true` and `banner_reason`; a verified
  grade A to D carries `banner: null`, `excluded_from_totals: false` and the `grade`.
  The figures stay (they are step 4's deterministic low, base and high, not a result);
  nothing else in the response changes.

Findings that enable one effect join that effect's one loss event, so five findings
on one payment loss never multiply it; every observation of one SPINE effect joins
one event too, and an event reads, for each input, the larger loss across all its
effects, so joining never understates. Under grouping v2 (the owner's decision of 12
Oct 2026) an effect within 24 hours of any member of an event joins it, and a
hypothetical effect takes part in every event of its key and is priced in ONE: the
event where it adds the most at base. Every other event lists it, joined, and reads
none of its figures, so its loss is counted once, never once per event. Adding an
effect never splits an event or moves one. At base the scenario's gross falls only
when an added effect merges two events into one loss, which counts their shared pool
once. At high or low it can also fall when the pricing moves to another event
(spec, section 24.9). An observed figure (`MYTHOS_OBSERVED`) is
only a rate, a count or a duration, and its evidence is exactly the SPINE effect
digest it was seen as (then, if wanted, a space and a note), never a mention of it; a
parameter set's money figure is never observed. Every
check runs before the build's transaction, which only inserts. Every reference is
looked up in the path's deployment only. A fault in the builder leaves these two routes unserved and nothing
else; neither is a stop.

### The simulation

`assurance/economics/simulation_service.py` simulates a stored scenario version
(section 25): every parameter draws from the distribution it states (one that holds
its own low, base and high: a continuous one from both sides, its base between its P5
and P95, its median between the low and the high, and at least half its mass between
them, never on a fixed row, a count on any row but the frequency included; the
frequency, whose figures are values of its rate, by the rate its count implies: its
exact mean, and the implied rate's median and half its mass between the low and the
high, a fixed rate only as a Poisson of it), or a point mass, or an expert's
PERT, or, where the
builder joined several effects' figures, from each of theirs taking the larger loss,
or is refused; the frequency is the one the parameter-set version states; every
parameter is drawn once per simulated year; every formula runs as
a vectorised twin proven equal to it, and what nothing uncertain reaches is step 4's
Decimal figure; insurance applies per event; and the run is recorded once per scenario
version, input digest, seed and draws as a `SimulationResult`, with every version and
limit it rests on and no float. It never raises, and nothing Django loads at start
imports it or numpy; step 6's simulate route (below) calls it.

### The Validity Card and the receipt

`assurance/economics/validity_service.py` takes a stored `SimulationResult` (section
26): it ranks the parameters by their contribution to the variance of the gross cash
loss, on the run's own draws, with a P10/P90 tornado; grades the run A, B, C, D or
Unknown from its evidence mix, each figure, fixed or ranged, weighted by its share of
the base-case level (an additive decomposition at base: each cash component's share
split among its own inputs -- by its additive terms first where its formula is a sum,
such as a fixed fee plus a rate times hours -- a frequency one half), with spec-v1's
downgrades and every figure's freshness -- under a policy the gross and the retained
cash apart, the lower grade the headline; and records the Financial Exposure Validity
Card, every field of
the owner's table, once per result, bound to the system fingerprint the scenario was
built in (or, for a scenario built without one, the deployment's when the card is
issued, said so). `assurance/economics/receipt_service.py` builds the signed Financial
Exposure Receipt with `mythos_core.exposure_receipt`, has the engine sign it as it
signs assurance receipts, records it once per result only after it verifies against
the engine's published economics-receipt keys, and verifies a stored one against the
release it was made under, refusing a tampered card, result, source snapshot,
signature or row with its code. Neither raises, and nothing Django loads at start imports
either; step 6's simulate route (below) calls both.

### The scenario endpoints and the report

A third route module (`assurance/economics/report_api.py`), imported guarded in a
guard of its own, serves what steps 5, 7b and 8 record (section 27):

- `GET /api/assurance/deployments/<uuid>/economics/scenarios/<scenario uuid>/`: the
  scenario version, every parameter it reads with its provenance and what reads it,
  its validity (each simulation result with its grade) and its evidence as SPINE ids,
  never copies;
- `POST .../economics/scenarios/<scenario uuid>/simulate/`: `{"seed": ..., "policy":
  "standard_100k" | "quick_10k" | "detailed_1m", "receipt": false}` runs, or returns,
  a simulation through the simulation service (idempotent: the same inputs return the
  stored result, 200; a new one is 201), then issues its Validity Card, its chart
  series and, when asked, its signed receipt, each once per result; an admin or
  analyst only;
- `GET .../economics/scenarios/<scenario uuid>/results/?simulation=<uuid>`: the report
  JSON of one result (else the scenario's latest), `mythos.economics.report/v1`:
  identity and versions, loss events and components at low, base and high, P10, P50,
  P90, mean, expected annual loss and severe-but-plausible with their bands and every
  "not reported" reason, the exceedance curve and histogram, the sensitivity
  tornado, the grade, the Validity Card and the receipt's reference, limitations and
  unknowns.

The report is deterministic: the same stored rows give byte-identical canonical JSON,
with no clock but the stored times, and it carries its own `sha256:` digest. Every
stored row it serves is checked first against its digest and its result (a card's
grade is its document's, never its column's); a result whose rows fail a check is
served as a refusal, `stored_row_unverified`. Money is shown at the currency's minor
unit (0 places for JPY, 3 for KWD). A refused run is served as its refusal, never as
figures. A result graded Unknown, refused, unverified, or not graded still shows what
figures it may, with `banner: "Unknown: not for capital decisions"` and
`excluded_from_totals: true`, and nothing may sum it into a total: `may_be_totalled`
fails closed (the report's own digest, and a grade of A to D). The builder's events
route (above) applies the same rule to the version's latest result. One 120 s deadline
bounds a simulate request, shared by the run, the analysis and the series.
Access, tenancy (404), strict JSON, 64 KiB and the 503 while the currency table
cannot be read are the parameter set's; a run the engine cannot make now is 503 and
records nothing. None of the three is a stop, and a fault in this module leaves only
these routes unserved. A residual run under a remediation option (below) is never the
scenario's exposure: `results/` and the scenario document serve only its own runs.

### The remediation option and its ROI

A fourth route module (`assurance/economics/remediation_api.py`), imported guarded in a
guard of its own, serves ONE remediation option per scenario version and its economics
(section 28; the owner's specification, section 21):

- `POST .../economics/scenarios/<scenario uuid>/mitigations/`: records the version's
  one option, authored by the signed-in admin or analyst: its implementation cost and
  annual recurring cost (money, low/base/high, a source), time to implement,
  dependencies (text or SPINE ids, never copies), and its control effect -- a
  frequency reduction and/or a magnitude reduction, each a ratio with low/base/high and
  a source, acting on every component or on the families or components it names; an
  observed effect cites the Achilles retest it was observed in, by its digest, and is
  refused unless the retest gate's own verdict is that the control held. 201, the same
  option again 200, another 409 (a new option is a new version);
- `POST .../mitigations/<option uuid>/simulate/`: `{"seed": ..., "policy": ...}` runs, or
  returns, the current run (where missing) and the residual run -- the same engine,
  seed and streams (common random numbers), each occurrence of a component the option
  acts on kept with probability `1 - r_f` and multiplied by `1 - r_m` -- each with its
  Validity Card, under one 120 s deadline; idempotent; an admin or analyst only;
- `GET .../economics/scenarios/<scenario uuid>/roi/?simulation=<uuid>`: the ROI
  document, `mythos.economics.roi/v1`: current and residual expected annual exposure,
  the expected reduction, the first-year investment, the risk-adjusted ROI (decision
  support, not a guaranteed return; not meaningful over a zero investment), the payback
  in years (never negative or infinite), the P90 and P95 tail reduction, utility
  retained, and the confidence delta between the two runs' cards.

The ROI document is canonical JSON with its own digest, built from stored rows only,
each run verified as the report verifies one; where either is Unknown, refused,
card-less or unverified it carries the banner and `excluded_from_totals: true`. Beside a
first-year investment or a reduction shown as 0.00 there is no ROI and no payback, and a
cost finer than the currency's minor unit is refused. Under a policy the headline is the
retained cash, with the gross-cash reduction, ROI and payback shown beside it, and the
deployment's standing decision is stated ("this ROI does not override it"), never as a
veto. The hard security veto always wins: where a finding the scenario rests on is a
hard release blocker in Mythos policy (active and high or critical, or accepted with an
acceptance that lapsed, never named an end or was made at a lower severity), or an
observed effect's chain is violated, the document says "remediation is required
regardless of ROI" and the ROI and payback are display-only; a blocker status that
cannot be read is `"unknown"`, which applies. A residual run is never exposure: its
report is marked `residual_of`, `may_be_totalled` refuses it (and anything that is not a
report, the ROI document included), and it is never receipted. None of the three routes is a stop, and a fault in this module leaves only
these routes unserved.

### The live feeds (step 10, waiting on the owner's keys)

Four official publishers are wired (spec, section 29): the ECB's euro reference rates
(SDMX, labelled an informational average, not a transaction price), the Fed's H.10
rates (with each series' quotation convention), FRED with ALFRED vintages, and BLS PPI
and wage series. `manage.py fetch_financial_source <source> [--as-of DATE]` fetches
one through the platform's outbound client and records it as a new platform-wide
source version at `unverified`, append-only and deduplicated by the answer's normalised
payload hash; a malformed or partial answer is refused with a code and nothing of it
is kept. It sends nothing until the owner sets the keys (`ECONOMICS_FRED_API_KEY`,
`ECONOMICS_BLS_API_KEY`; `source_key_missing` otherwise) and turns on
`ECONOMICS_LIVE_FEEDS_ENABLED`, and every source's licence stays `unreviewed` until the
owner's review. Each source has a freshness SLA (ECB 3 days, H.10 10, FRED and BLS
monthly 45): a stale source lowers the grade of every figure it feeds one step, and one
past twice its SLA makes the Validity Card's claim stale and refuses the receipt
(`source_stale`). An FX or cost-index source behind a production receipt must be
`authoritative` (`source_not_authoritative`). `GET
/api/assurance/deployments/<uuid>/economics/data-health/` lists each feed's latest
version, age, SLA, state, last fetch failure (its code) and the Unknowns it causes.
A run uses the newest usable version of a source whose observations cover its as-of
date. The HTTP client's own log records (urllib3's request lines) withhold every query
string, so the FRED key reaches no log. The adapters are tested against format-faithful
fixtures, not recorded responses, in `tests/fixtures/economics_feeds/`, under a socket
guard; none of it is a stop.

### The portfolio

A sixth route module (`assurance/economics/portfolio_api.py`), imported guarded in a
guard of its own, totals a deployment's scenarios from their draws (Economic Exposure
E5, `docs/economics/spec-v1.md` section 30):

- `POST /api/assurance/deployments/<uuid>/economics/portfolio/simulate/`:
  `{"seed": ..., "policy": "quick_10k", "reporting_currency": "USD",
  "valuation_date": "2026-10-06", "normalization": {...}, "groups": [...]}` takes each
  current scenario version's latest exposure run that `may_be_totalled` admits (never
  a remediation option's residual run), lists every other with its reason (Unknown,
  refused, unverified, not graded, never simulated, not annual, superseded, inputs
  changed, or a currency that cannot be normalised), draws the included scenarios
  again on one seed with aligned years, scenarios in one correlation group (two at
  least, a strength from 0.000001 to 10 with a source type) sharing one Gamma driver
  of their annual rates, counts a loss event two scenarios share (one SPINE effect, or
  step 5's key and window) once a year, at the largest of their losses of it that
  year, normalises every draw into the reporting currency at the valuation date
  before summing, and records the result (idempotent: the same inputs return it, 200;
  a new one is 201); an admin or analyst only;
- `GET /api/assurance/deployments/<uuid>/economics/portfolio/?result=<uuid>`: the
  portfolio's report (else the latest), `mythos.economics.portfolio-report/v1`: P10,
  P50, P90, mean, expected annual loss, severe-but-plausible and the expected
  shortfall per line, each included scenario's own figures over the same years (the
  portfolio is at least each), each scenario's contribution to the mean and to the
  tail (summing to them exactly), the groups, the shared events, every exclusion with
  its reason, the grade (no higher than the lowest included scenario, lower for an
  expert's correlation strength; none for a refused portfolio) and the banner.

The report is built from the stored rows only and is deterministic, with its own
digest; every stored row it rests on, each included scenario's result, card and
series among them, and the record's binding to its inputs, is checked first, and a
failure is served as a refusal. No transaction or lock is held during the draws.
Access, tenancy, strict JSON, 64 KiB, the 503 while the currency table cannot be read
and the one 120 s deadline are step 6's. Neither route is a stop, and a fault in this
module leaves only these two unserved.

## When a dependency fails

`tests/test_no_fault_makes_a_decision_ready_or_holds_a_stop.py` makes each
dependency of the deployment decision fail, one at a time. It asks decision-support,
the recompute and the receipt what they serve, and times every stop against a 1 s
bound. Its `MATRIX` is the full table. What each fault reads as:

- A table the decision is computed from cannot be read (findings, claims, retest
  obligations, latent conditions, the asset inventory, the workflow chains), or the
  chain composition raises. Decision-support and the recompute answer 500, and the
  stored decision stays the one its inputs implied. Nothing serves READY.
- A claim revoked or contradicted while the decision cannot be recomputed still
  lands. The decision it moved is held at `needs_more_evidence`, or where it stood if
  that is worse. The answer carries `"decision_recomputed": false` and names the
  error's type in `decision_unrecomputed`. The held decision carries no policy stamp,
  so the first publishing read that can recompute it does. Until then those reads
  fail rather than publish it.
- The pause, the dispatch kill switch and a claim take-down load their row with
  nothing a stop does not need. A failed read of the findings, chain outcomes, assets
  or transition log no longer drops them.
- The clock stepping back: the decision is judged no earlier than the deployment
  record's last write, so an acceptance the record has seen lapse does not stand
  again. A step back that nothing wrote across is not seen.
- A stored check-coverage record whose rows cannot be read counts them as checks
  with an unknown outcome (`audit_incomplete`). It never reads as "not reported".
- An engine answer whose findings list holds nothing readable is no report. It is
  not ingested as a clean completed scan.
- The outcome keyring unreadable: no chain outcome can be shown signed, and the
  decision reads `needs_more_evidence` until the keyring is back.
- The rules are module constants, so no policy file is read. The pin is read before
  any rule is applied, so a decision is stamped with the rules it was read under. One
  computed while a rule moved names the old rules, and the first publishing read
  recomputes it under the rules in force.

What does not hold, and is named in `MATRIX` with its severity: a database that
refuses every write records no stop (each answers 500 and claims nothing). A pause
cannot land while the transition log cannot be read or the decision cannot be
written; the failsafe relay still does. A take-down while the decision cannot be
written, or its transition log read, lands, but leaves the stored decision as it was
until the next refresh. An engine answer that holds readable findings beside rows
this side cannot read ingests the readable ones and drops the rest uncounted, so
one `info` finding beside unreadable rows reads `ready`.

## Verifying a receipt

`GET /api/assurance/deployments/<uuid>/signed-assurance-receipt/` returns a
deployment's Assurance Receipt beside the DSSE envelope the engine signed it in.
`assurance-receipt/` returns the unsigned copy. The receipt is specified in
[`docs/receipt-spec/`](docs/receipt-spec/README.md); the current version is
`mythos.assurance.receipt/4.1`. The specification covers every member, the
canonical form and digests, the signature, the verification steps with every
refusal, and how older versions are read. Anyone can verify a receipt offline with
the specification and `tools/verify_receipt.py`, which needs only Python and
`cryptography`:

```bash
python tools/verify_receipt.py signed-receipt.json --keyring keyring.json
python tools/verify_receipt.py signed-receipt.json --keyring keyring.json --max-age 86400
```

Take the keyring from the engine's `GET /api/assurance/keyring` (this backend does
not serve it), out of band from the receipt. The exit status is 0 when the receipt
is verified, 1 when it is refused (the first line names the reason), and 2 when the
verifier could not run. A verified receipt attests integrity and provenance only,
and does not say the assessment is correct.

A signed 4.1 receipt carries the time it was issued, `issued_at`, inside the
signature: this backend's clock when it had the receipt signed, in UTC. An
`issued_at` edited after signing fails the signature, and the verifier prints the
signed time. It is the issuer's clock, not proof of when the state held, and how
old is too old is the reader's call: `--max-age SECONDS` refuses a receipt issued
longer ago than that (`stale`), and a 4.0 receipt, which carries no signed time
(`no_signed_time`). A 4.0 receipt still verifies, and the verifier says its issue
time is not signed.

Every receipt version ever emitted reads back, 1.0 included. The verifier and
`receipt_schema(version)` name each one and who emitted it, and say what it lacks
against the current version. 2.0 was emitted in two shapes under one version string
(#56's five-member `coverage` and #67's nine), and each is read and named as the one
it is. No route signed a receipt before 3.1, so an envelope over a 1.0, 1.1, 2.0 or
3.0 receipt is refused (`never_signed`). `tests/fixtures/receipts/` holds a 1.0
receipt and one of each 2.0 shape, generated from the commits that emitted them
(`generate.py`, with each vector's provenance beside it).

`tests/test_receipt_spec_conformance.py` builds vectors from the real routes and
from those fixtures. It holds the verifier to the backend's own answer on every
check the backend makes, and to the known signer and the known issue time on the
signature and the age, which the backend never checks.

## Tests

```bash
pytest
```

The suite uses `tests/settings_test.py`, which reuses the real settings and
overrides only the database, mail and throttling. The engine contract tests in
`tests/test_engine_contract.py` skip unless `CYBERENGINE_URL` and
`CYBERENGINE_OPERATOR_KEY` are set, because they need a live engine.

The frontend's tests run with `npm test` (`node --test`, Node 22.6 or later):
`frontend/src/lib/refresh-token.test.ts` and `frontend/src/lib/idempotency.test.ts`.

## What a span carries, and the advisories this service tracks

A span (`assurance/observability.py`) carries the deployment's primary key and
the step, never a deployment's name or a finding (`tests/test_assurance_tracing.py`),
and an exception that leaves one is recorded by its type alone (`error.type`, and
the class name as its status): left to the OpenTelemetry SDK's defaults, an
exception raised while deriving claims went to the collector with its message,
stack trace and chained cause, quoting whatever it was reading
(`tests/test_an_exception_reaches_a_span_as_its_type_alone.py`). The caller gets
that exception even when ending the span raises.

`advisories.toml` registers the upstream advisories against the dependencies on
the path from an engine's answer to this service's record, with the test of this
service's own that pins each; `tests/test_every_registered_advisory_is_fixed_here.py`
fails in CI, with no network, when one is installed or declared at an affected
version. Two Pydantic AI advisories fixed in 1.107.6 and 2.44.0 started it
(GHSA-4x9p-g9wm-8q7f, telemetry content escaping a disabled-content setting;
GHSA-22h6-qm39-v87j, a domain list bypassed by a hostname the resolver normalises
differently). Pydantic AI is not a dependency of this service, directly or
transitively; the same behaviours are tested on its own spans and on the
scan-target guard (`tests/test_the_target_guard_decides_on_the_host_the_client_dials.py`).
Nothing here says any deployment was affected.

The register reads every way a requirement can be declared -- `-r` and `-c`
includes, `\` continuations and `--hash` options, setup.py through `ast` --
probes both ranges' edges so an exact pin inside an affected range is seen, and
fails on any declaration it cannot read rather than passing over it.

## Where a secret cannot go

A credential this service holds or is sent reaches no answer, record, export,
e-mail, log, file, span or command output: a connector's or posture binding's
token, the key they are encrypted under, the engine's `X-API-Key`, the closure
forward's `MINOTAUR_OUTCOMES_KEY`, the gate's and the observed-effect service's
tokens, the closure-evidence and failsafe tokens, a signing key, a proxy's
userinfo, a password, the economics feeds' FRED and BLS keys. And an error page
says that something failed, never what it was given or what the exception said.

`tests/test_no_planted_secret_leaves_through_a_sink.py` holds the service to that.
It plants a distinct canary in every one of those origins, and in what a tenant
sends (a request body, a scan target's userinfo, an uploaded file, a closure
document); drives a scan that completes, fails, times out and is reconciled, and
is stopped (its Stop delivered, and owed and delivered by `deliver_owed_stops`),
connector pushes and posture reads that succeed, fail and run past their
deadline, a closure forwarded and retried, the gate's read, an observed effect, a
signed receipt, the failsafe's poll and a stop draft, uploads, every outbound call
with a credentialed proxy in the environment, and a route that raises; and then
searches every sink whole, in every encoding (the engines' search, Athena-Engine
#76): every API answer, receipt and pack, the PDFs, e-mail, every record of every
logger at every level with stdout and stderr, every row of every model, every file
under `MEDIA_ROOT`, every span, and every management command's output. A route,
model, management command, file writer, log configuration or span attribute it
does not classify fails it, so a new sink cannot ship unchecked. What a tenant
sends is the record itself in most of those places; where it is found is printed
(`test_the_observed_matrix`), never claimed absent.

Every request this service sends with `requests` itself -- to the engine, from the
defender gateway, to a customer's connector or posture source, and the closure
forward to Minotaur -- goes through `safety/outbound.py`: no `.netrc` login is
read, an error is cut to the scheme, host and port of any URL in it with every
header value withheld, and an answer is read with every credential the request
carried withheld from its body (`tests/test_no_outbound_call_follows_a_redirect_or_reads_the_environment.py`).

- **The engine** (the engine client: a scan's launch, its status, its Stop, file
  uploads and every other engine call; and the defender gateway's `/defend`, which
  asks the same engine) follows a redirect only while it stays on
  the engine's host: a 307 or 308, and a 301, 302 or 303 answering a GET, to the
  same host (compared case-insensitively after IDNA) at any port, with the scheme
  kept or moved from http to https, at most three hops, sending the method, body
  and key again. Another host, https to http, a 301, 302 or 303 answering a POST,
  and a fourth hop are refused and nothing is sent where they point. It is
  reached through the proxy the process environment names (`HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY`, read by `urllib.request.getproxies()`), and directly
  for a host `NO_PROXY` names; a proxy's userinfo is withheld from every error
  and answer. An engine a deployment reaches only through its proxy, or that
  moved its stop route or onto https, still hears a scan's Stop.
- **Everything else** -- a connector, a posture source, the closure forward --
  follows no redirect at all and reads no proxy: a deployment
  that reached a connector or posture source through `HTTP_PROXY` or `HTTPS_PROXY`
  must reach it directly, and a call site that comes to need a proxy names it in
  a setting of its own.

A scan target's login (`user:password@` in its URL) is kept on the scan, since a
reconcile sends the launch again unchanged, and is withheld from every error the
engine client raises for a call carrying it, and from every text the scan stores
or answers: an engine's refusal may quote the launch back. It is never withheld
from the engine's answer before it is read, so a login can never rewrite the run
id a Stop names.

## Before deploying

```bash
python manage.py check --deploy --fail-level WARNING
```

CI runs this and it must stay clean. `DJANGO_SECRET_KEY` is required outside
development, and the process refuses to start without it.

## Connector dispatch that a stop owes

A pause, or any recompute that leaves a blocking decision, never waits on a
connector. When the deployment's dispatch policy opts into the decision trigger,
the stop records the dispatch as owed (a `DecisionDispatchDue` row, in the stop's
own transaction) and a background thread pushes the findings after the stop has
answered. If the stop could not write that record, its thread is started anyway
(past any bound) and writes the record before anything else. What is not finished
stays recorded, and three things retry it:

- the thread itself, 2 s and then 8 s later;
- a sweeper in every serving process. The WSGI and ASGI entry points start it on
  the process's first request -- never at import, so under a pre-forking server
  (`gunicorn --preload` included) each worker has its own and the master none --
  5 s after that and then every `ASSURANCE_DISPATCH_SWEEP_SECONDS` (default 300;
  `0` turns it off). A sweep claims each row it starts, so several processes share
  the backlog instead of racing for the same rows;
- `python manage.py retry_blocking_dispatches`, which you should also run on a
  schedule. It exits non-zero while anything is owed, so the scheduler reports
  it. For example, cron every five minutes:

  ```cron
  */5 * * * * cd /srv/athena && .venv/bin/python manage.py retry_blocking_dispatches >> /var/log/athena/dispatch-retry.log 2>&1
  ```

  or a systemd timer with `OnUnitActiveSec=5min` running the same command.

Only one runner pushes for a deployment at a time, in any process: a run claims
the row first, and a claim left by a process that died lapses after five minutes.
Every push is recorded as `sending` before the request goes out, with the marker it
carries. Before a first push, and for a push whose answer was lost, the provider is
asked for the finding's issue, oldest first, 100 a page:

- **Jira**: one JQL over the marker label, the older labels `athena-<uuid>` and
  `<uuid>`, and `text ~ "<uuid>"` (every issue Athena ever created says
  `Athena finding: <uuid>`), through `/rest/api/3/search/jql` (Jira Cloud), falling
  back to `/rest/api/2/search` (Data Center and Server) when the first is missing;
- **GitHub**: the issues list by each of those labels, then the search for the uuid
  in bodies (GitHub drops the labels of a token without push access; the create
  then says so);
- **ServiceNow**: `correlation_id`, which every release has sent.

Each issue Athena creates carries its marker twice: the label
`athena-<installation>-<finding uuid>`, and the body line
`Athena marker: <label> <tag>`, where the tag is an HMAC, keyed by a secret only this
backend holds, over the installation id, the connector and its destination (base URL
plus repository, project or table), the finding and its deployment -- so a tag read
in one tracker never verifies in another. Only an issue whose tag verifies, or the
one already recorded for the finding (read directly by its id), is adopted; of
several that verify, the one created first, since a copy (a Jira clone, a pasted
body) is always made after what it copies. Anything else the search matches -- a
copied label, a planted body, a forged tag, another installation's or another
tracker's tag -- is ignored and named in a WARNING; it never holds a dispatch.

An issue in a format older than tags (master's `Athena finding: <uuid>` body, or an
earlier label) is never adopted: anyone who can edit an old issue can make it
mention a finding. One the provider says was created before this installation began
tagging is a possible duplicate: the ticket filed for the finding names it in its
body, and a WARNING names it too, so a person can close one of the two. A push an
earlier release made (no marker recorded on its attempt) is pushed again the same
way when the look names such issues; when nothing at all is found for it, it is
held, not pushed again blind.

A closed issue for the finding is not reopened and not duplicated: it is commented
on (on the first push and on a lost answer's alike), and the attempt is recorded
`sent_to_closed`, with a WARNING and a note on the attempt that the tracker says the
work is done while the decision still blocks. Where a push cannot be looked for
(Splunk HEC), or is held, it stays owed until someone records what happened:
`python manage.py reconcile_dispatch_attempt <attempt uuid> --provider-has-it --by <you>`
(or `--provider-lacks-it`). The deployment's `dispatch-attempts` read shows what is owed.

The installation id and the marker secret are random, generated once and kept in
the database (`AssuranceInstallation`); neither is derived from `DJANGO_SECRET_KEY`,
so rotating that key changes no marker. `ASSURANCE_INSTALLATION_ID` overrides the id.
Every id the database has used is kept (`AssuranceInstallationId`) and a marker made
under any of them verifies, so setting or changing it after go-live files no second
ticket. A database restored into another environment (staging from production) is
the same installation, markers and all: to make it a separate one before it pushes
to a tracker production also uses, give it a new identity with
`python manage.py shell -c "from assurance.models import AssuranceInstallation as I, AssuranceInstallationId as J; J.objects.all().delete(); I.objects.all().delete()"`.

Settings, read from the environment (see `.env.example`):
`ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS` (default 4) runs push at once per process,
with at most `ASSURANCE_DISPATCH_MAX_WAITING_RUNS` (default 32) more threads waiting;
past that nothing recorded is started now, and the next sweep starts it. A dispatch
the stop could not record is started past that bound, but never past twice it.
`ASSURANCE_DISPATCH_SWEEP_SECONDS` (default 300; `0` off).
`ASSURANCE_CONNECTOR_DEADLINE_SECONDS` (default 30) bounds each connector request in
total, including name resolution. A value that is not a number fails
`manage.py check` (`assurance.E303`), is logged once at start, and the default is
used. `ASSURANCE_AUTO_DISPATCH_ENABLED=False` stops all of it without dropping
anything owed.

Logging. A stop's thread never writes to a log handler. A dispatch that is neither
recorded nor started is named at ERROR, with the `retry_blocking_dispatches
--deployment N` command to run: at once, in the stop's own thread, as one line to
stderr -- only if stderr can take it without waiting -- and, for the log handlers,
through the background log thread. When no thread can start, the record waits in
that queue (bounded, counted) until the next request, sweep or exit starts or runs
the writer. Everything else on a stop's path goes the same way, through a queue of
at most 1000 records (the oldest are dropped and counted); what is queued at exit is
written then, for at most 2 s.

**Migration `assurance.0043`** adds `marker` as a nullable column with no default: a
plain `ADD COLUMN`, so it copies no table and holds the write lock for no time
whatever the table's size, and code still serving from before it (migrate, then
restart) goes on recording its attempts, which read as an earlier release's. Code
deployed AHEAD of it cannot dispatch or push by hand (the columns are missing) until
it runs; stops are unaffected and what is owed stays recorded.
**Rolling back past `assurance.0043`** is refused while an uncertain attempt carries
a marker (code before it cannot look for it), and turns `sent_to_closed` back into
`sent`. **Past `assurance.0042`** it is refused while any
attempt is `sending`, because code from before it would push those again blind.
Check with
`python manage.py shell -c "from assurance.models import DispatchAttempt as A; print(A.objects.filter(outcome__in=['sending','unknown']).count())"`,
and settle them first (let a run finish, or use `reconcile_dispatch_attempt`).

## Retries and duplicates

A request sent again -- its answer was lost, or the client stopped waiting -- must
not do its work twice. What each operation that reaches outside this backend does
(`tests/test_firing_twice_makes_one_effect.py` fires each one twice):

- **A scan launch** (`POST /api/pentest/scan/`, `/api/pentest/llm-scan/`), **a report
  resent** (`POST /api/pentest/scans/<uuid>/email/`) and **a finding pushed to a
  tracker by hand** (`POST /api/assurance/deployments/<uuid>/connectors/<name>/push/`)
  take an `Idempotency-Key` header, 1 to 255 printable ASCII characters. The first
  request with a key is recorded for that account and route, with a digest of the
  request (body, query and the scan or deployment it names) and the answer it got.
  The same key and request again is given that answer (`Idempotent-Replayed: true`)
  and starts nothing. While the first has no answer recorded -- still running, or it
  raised or died first -- it is 409, its outcome unknown; the same key with another
  request is 422. Authentication and the route's permissions are checked on every
  request, a replay included. Keys are kept 24 h (`IDEMPOTENCY_KEY_TTL_SECONDS`), at
  most 1,000 per account, oldest forgotten first (`IDEMPOTENCY_KEYS_PER_ACCOUNT`), and
  an answer is kept whole up to 1 MiB (`IDEMPOTENCY_MAX_RESPONSE_BYTES`; a larger one is
  replayed as its status and top-level fields). A forgotten key is a new request.
  **Without a key nothing changes: a request sent again scans again, mails the report
  again or files a second ticket.** The athena-dashboard server does not send one yet.
  This backend's own frontend does, on the one keyed route it calls (the Penetration
  Testing page's Start Scan, `frontend/src/pages/pentest.tsx` through
  `frontend/src/lib/idempotency.ts`). Each press gets its own key. The key is sent
  again only with the same request, and only while that request's outcome is unknown:
  its answer never arrived, or the backend answered 409. A replayed answer is shown
  as that scan's answer, never as a new scan, and a 202 is shown as still running,
  never as complete. A 409 says the scan may or may not have started and points to
  the scans list, which is read again. A 422, or a 400 about the key, is shown as a
  bug in the page. Nothing is sent again with a new key on its own. The frontend
  calls none of the other three keyed routes (`frontend/src/lib/idempotency.test.ts`
  fails on a call to one that does not send its key).
- **Automated dispatch** is one `DispatchAttempt` per finding and connector (above):
  pushed once, looked for by its marker after a lost answer rather than pushed again,
  and sent to a webhook with its operation id as `Idempotency-Key`. A blocking-decision
  dispatch asked for by several pauses is one owed row.
- **Claims**: a re-derive with nothing moved writes no version and no event; an
  invalidation check run again opens no second retest; a person's move sent twice is
  refused the second time (400); an evidence item invalidated twice is refused the
  second time.
- **Stops are never deduplicated.** A pause, revoke, contradiction, stand-down,
  terminate, an engagement's authority withdrawn, a scan's Stop, an operator demoted
  or removed is processed every time it arrives, with or without a key: the key is
  never read on a stop route (`safety.stops`). A revoke or contradiction sent again is
  recorded again on the claim; its status moves once.

### A scan launch whose engine answer was lost

The backend's launch of a scan on the engine (`POST /api/scan`) carries an
`Idempotency-Key` of its own: the scan's, one per scan record, made from its uuid
(`PentestScan.launch_key`). It is not the key a client sends this backend. That one
keeps a request to this backend from running twice; this one keeps one scan's launch
from starting two runs on the engine, which answers the same key and request with
the first launch's answer and starts nothing (athena-engine #77). A stop never
carries one.

What the launch's answer records on the scan:

| What happened to the launch | The scan reads |
|---|---|
| The connection to the engine was never made: refused, no route, the name did not resolve, the connect timed out | `failed`: nothing was sent |
| The engine refused it (a 503 or other refusal it wrote, a 429), or its run ended failed or stopped | `failed`, with the run id where the engine named one |
| The engine named a run that is still going, or named one in an answer this backend cannot read | `pending`, with the run id |
| The request was written and no answer the engine wrote came back: the read timed out, the connection broke, a gateway answered 502 or 504, or a 5xx carried nothing the engine wrote | `unknown`, with the reason in `error_message` |

`unknown` is never `failed`: the engine may have started a run, and a failure would
license launching it again. The launch answers it 202 with `status: "unknown"` and
the reason. (The Penetration Testing page shows any 202 as still running; it does not
read `status` yet.) An unknown scan is not ingested and has no report.

It is reconciled by `POST /api/pentest/scans/<uuid>/reconcile/`: the same launch,
sent again with the same key.

- The engine replays the first launch's answer: its run is adopted and read as it
  stands now -- `pending` while it runs, `completed` with its findings and report,
  `failed` if it failed or was stopped.
- The engine holds the key with no answer recorded (409), or for another request
  (422): still `unknown`, and it says so.
- The engine refuses the resend before it reads the key (it is paused, stood down or
  terminated; the scope or engagement was withdrawn), or cannot be reached: still
  `unknown`, naming the refusal. A refusal of the resend says nothing about the first
  send.
- The engine answers as to a new launch: it never saw the first send, and this run is
  the scan's first and only one.
- A refusal naming a run that never started (a full pool): `failed`, as at launch.

Nothing sends a launch again on its own -- not a read of the scan, not a timer. A
reconcile is asked for by an admin or analyst who can see the scan, and is judged as
a launch is: the engagement must still authorise the target, the target must still
be in bounds, and the preflight gate is asked again. Otherwise nothing is sent and
the scan stays `unknown`. A reconcile mails no report. Only `unknown` scans are
reconciled. Not covered: the LLM scan's launch (`/api/llm-scan`, a route athena-engine
does not serve) carries no engine key and is not reconciled.

**While a Stop is owed on the scan, a reconcile sends nothing to the engine** -- not
the launch, not the preflight gate's check -- and answers 409 saying why. When the
engine never saw the first send, the resend is that launch: it would start the scan
the Stop stops, and athena-engine offers no lookup by launch key that cannot launch.
The scan stays `unknown` and the Stop owed. A reconcile claims the resend in one
statement, only while no Stop is owed (the scan reads `pending` while the resend is
out), so a Stop asked before the claim holds it back, and one asked after it is a Stop
asked while a launch is under way (below).

### A scan's Stop

`POST /api/pentest/scans/<uuid>/stop/` (an admin or analyst who can see the scan)
stops the scan's run on the engine: `POST /api/scans/{run_id}/abort` for exactly that
run, never `abort-all`. It is a stop (`safety/stops.py`): no gateway or throttle holds
it back, the failsafe service token is accepted on it, and it is processed every time
it is sent. It is recorded on the scan before anything is sent to the engine, and
answered 200 once the engine has answered it for the run (it stopped the run, the run
had already ended, or it has no such run), or 202 while it is owed.

A Stop is owed while the scan names no run -- its launch's answer was lost, or the
launch is still waiting for the engine's answer -- and while the engine cannot be
reached. The Stop's answer and the scan's read (`GET /api/pentest/scans/<uuid>/`) say
so plainly: `stop.state` is `owed`, and `stop.detail` says the Stop is not delivered
and has not stopped the run (or, where the engine did not answer the abort, that the
run is not known to be stopped). `stop_saved` in the answer says only that the Stop
is kept on the scan. It is sent to exactly the run the moment the run is named: by
the launch -- a first one, or a reconcile already sending -- as the engine names it,
before anything is collected; by the next Stop; and by
`python manage.py deliver_owed_stops`, which sends every owed Stop whose scan names a
run and exits non-zero while any is owed. Run that on a schedule too, like
`retry_blocking_dispatches`. A Stop never sends a launch again to learn the run: a
stop starts nothing.

A Stop owed on an `unknown` launch names no run and holds every reconcile back, so it
stays owed: if the launch reached the engine, that run is not stopped by it. Nothing
here can deliver it until athena-engine offers a lookup by launch key that can never
launch; with one, a reconcile would look up first, and an owed Stop would be sent
whenever the lookup names a run.

**Migration `pentest.0019`** adds the Stop's three columns as nullable (a plain
`ADD COLUMN` each) and the `unknown` status. Rolling it back drops the Stop record of
every scan, owed Stops included: run `deliver_owed_stops` until it exits zero first.
Code from before it reads an `unknown` scan as neither pending nor completed, so it
makes no report of one and ingests nothing from it.

## Secrets

Nothing belongs in source. A Google app password for the company mailbox and a
Django secret key were both committed as default arguments; the password must
be treated as disclosed and reissued, since removing it from the file does not
remove it from git history.
