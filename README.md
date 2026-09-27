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

A stop is never sent to the engine and never refused by it, in either mode, and
no throttle refuses or counts one. The stops are listed in `safety/stops.py`:
a pause (`{"paused": true}`; a lift is start-direction and is not a stop), a
claim revoked or contradicted, a failsafe pause, stand-down or terminate drafted
(not a resume or release), a failsafe command signed or cancelled, the three
stop-lane reads (the failsafe state, the command list, and a command's detail),
the engines' poll with its token, a deployment's automated dispatch switched
off, an engagement's authority withdrawn (moved off running, scope emptied,
window closed, or deleted), and an operator demoted (never promoted) or
removed. A token refresh whose refresh token verifies and has not been spent is
exempt the same way; a refresh spends its token (`token_blacklist`, with
rotation), so a used one is judged like any other bad token.
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
lift, a resume or release draft, an operator demoted or removed, any other read
or write, the engines' poll, a refresh -- the header is ignored,
and so is a token that does not match: the request is judged and authenticated
exactly as if the header were absent. A stolen token can stop things and read
the stop lane; it cannot start anything, nor remove an operator. The token is compared as HMAC-SHA256
digests in constant time, and only a match costs a database read. The
athena-dashboard server will present it on its stops in a follow-up; until then
it signs in with its service account's password as before.

### Sign-in and the stop lane

Failed password sign-ins are limited, and only failures count: per address and
username (`DJANGO_THROTTLE_SIGN_IN`, default 10/min), where the username is the
one authentication looks up (trimmed as SimpleJWT trims it, NFKC-normalised
and case-folded, so every spelling of one account shares one budget), and per
address across every username (`DJANGO_THROTTLE_SIGN_IN_ADDRESS`, default
60/min). An address past either is answered 429 before any password is hashed.
A successful sign-in clears only its own address-and-username count. So a
sign-in from an address under a guessing flood can be refused, the operator's
own included if they share the attacker's address; no stop needs a password
sign-in (the service token, or an existing session and its refresh).

A stop draft is never throttled, so one account may have at most
`FAILSAFE_MAX_OUTSTANDING_STOP_DRAFTS` (default 20, at least 1) stop commands
awaiting signatures; the next is answered 429 naming them, to sign or cancel.
The command list and the state view list the stop commands awaiting a signature
first, never cut by their row caps. The state view waits for the engine's live
state `FAILSAFE_STATE_ENGINE_SECONDS` (default 2) at most.

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

A held Achilles signed still counts as demonstrated, so trusting an Achilles key
in the keyring lets a permit check move a deployment to `ready`. Whether it
should is an open decision, not a settled one.

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
