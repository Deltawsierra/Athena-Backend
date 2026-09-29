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
and an operator demoted (never promoted) or removed. A token refresh whose
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

## Tests

```bash
pytest
```

The suite uses `tests/settings_test.py`, which reuses the real settings and
overrides only the database, mail and throttling. The engine contract tests in
`tests/test_engine_contract.py` skip unless `CYBERENGINE_URL` and
`CYBERENGINE_OPERATOR_KEY` are set, because they need a live engine.

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

## Secrets

Nothing belongs in source. A Google app password for the company mailbox and a
Django secret key were both committed as default arguments; the password must
be treated as disclosed and reissued, since removing it from the file does not
remove it from git history.
