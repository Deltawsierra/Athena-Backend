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
Every push is recorded as `sending` before the request goes out. A push whose
answer was lost is looked for before anything is sent again:

- **Jira** by the label `athena-<installation>-<finding uuid>`, through
  `/rest/api/3/search/jql` (Jira Cloud), falling back to `/rest/api/2/search`
  (Data Center and Server) when the first is missing;
- **GitHub** by the same label, and by the marker in the issue body (GitHub drops
  the labels of a token without push access; the create then says so);
- **ServiceNow** by `correlation_id` and `correlation_display`.

A closed issue that already carries the marker is commented on, not reopened and
not duplicated. Several issues carrying one marker (a copied label) are never
adopted: the push is held. Where a push cannot be looked for (Splunk HEC), or is
held, it stays owed until someone records what happened:
`python manage.py reconcile_dispatch_attempt <attempt uuid> --provider-has-it --by <you>`
(or `--provider-lacks-it`). The deployment's `dispatch-attempts` read shows what is owed.

Set `ASSURANCE_INSTALLATION_ID` to a stable, per-environment value: it is part of
every marker, so a database restored into another environment never adopts this
one's issues. Unset, it is derived from `DJANGO_SECRET_KEY`, and rotating that key
changes the markers (issues created before cannot then be found by the look).

Settings: `ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS` (default 4) runs push at once
per process, with at most `ASSURANCE_DISPATCH_MAX_WAITING_RUNS` (default 32) more
threads waiting; past that nothing recorded is started now, and the next sweep
starts it. `ASSURANCE_CONNECTOR_DEADLINE_SECONDS` (default 30) bounds each
connector request in total, including name resolution.
`ASSURANCE_AUTO_DISPATCH_ENABLED=False` stops all of it without dropping anything owed.

**Rolling back past migration `assurance.0042`** is refused while any dispatch
attempt is `sending`, because code from before it would push those again blind.
Check with
`python manage.py shell -c "from assurance.models import DispatchAttempt as A; print(A.objects.filter(outcome='sending').count())"`,
and settle them first (let a run finish, or use `reconcile_dispatch_attempt`).

## Secrets

Nothing belongs in source. A Google app password for the company mailbox and a
Django secret key were both committed as default arguments; the password must
be treated as disclosed and reissued, since removing it from the file does not
remove it from git history.
