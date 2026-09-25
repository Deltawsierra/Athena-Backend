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

## Secrets

Nothing belongs in source. A Google app password for the company mailbox and a
Django secret key were both committed as default arguments; the password must
be treated as disclosed and reissued, since removing it from the file does not
remove it from git history.
