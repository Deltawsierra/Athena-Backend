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
- `observed_effect`: reserved for an independent collector. Nothing produces it
  yet.
- `unclassified`: signed by a trusted key for an engine not listed above.
- `attested`: typed in by an operator, or signed by a key the keyring no longer
  trusts.
- `unknown`: typed in without saying what it rests on.

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
time is not signed. `tests/test_receipt_spec_conformance.py` builds vectors from
the real routes. It holds the verifier to the backend's own answer on every check
the backend makes, and to the known signer and the known issue time on the
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
