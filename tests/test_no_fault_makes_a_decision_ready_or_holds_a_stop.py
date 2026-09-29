"""No fault makes a decision READY, and none holds a stop.

The Phase 4 chaos slice for SPINE's decision (roadmap item "Chaos / fail-closed
test suite"): the READY this backend computes, stores and publishes. Each
dependency the decision reads is made to fail, one at a time, and every decision
path is asked what it reads then:

    decision-support  GET  .../decision-support/    the decision as served, live
    recompute         POST .../recompute/           what is written to the stored
                                                    decision by its one writer, as
                                                    every publishing read then
                                                    serves it (read_decision)
    receipt           GET  .../assurance-receipt/   the decision the receipt serves
                                                    once a recompute has run under
                                                    the fault (read only here:
                                                    receipt.py is not this slice's)

Each is asked on a deployment whose decision the failing dependency holds back --
what the fault hides is what keeps it from READY -- so a fault read as "nothing
there" reads READY, and the cell fails. A CLOSED cell never reads READY or
READY_RESTRICTED: it answers the decision its inputs imply, or refuses (a 5xx, or a
publishing read that raises rather than serve a decision nothing computed). Once
the fault clears, every surface reads what the inputs imply again.

Every stop this backend owns (``safety.stops``) is timed under the same fault --
against a bound, on ``time.monotonic``, never a sleep -- and must take effect:

    pause              POST .../recompute/ {"paused": true}
    revoke/contradict  POST /claims/{uuid}/transition/: a claim revoked, another
                       contradicted -- the two moves that take a claim down
    dispatch-off       PUT  .../dispatch-policy/ {"enabled": false}
    failsafe-relay     the engine pause drafted and signed, then served to the
                       engine's poll (the relay: the backend signs nothing itself)
    scan-stop          PATCH /pentest/engagements/{id}/ {"status": "paused"}, the
                       backend's own scan stop (the engine's abort is the engine's)

`MATRIX` is the coverage table: every (fault, path) cell and what it shows.
CLOSED and HELD cells are tested below, one parametrized case each; so are
NOT_ON_PATH cells, where the path never reads the failing dependency and the test
shows the fault changes nothing there. LEFT_OUT cells are not proven here: each
names its repro and its severity, and has no test. ELSEWHERE cells belong to
another slice or repository, named. `test_the_matrix_names_every_cell` fails if a
cell goes missing, so a fault cannot quietly lose a path.

The faults are injected where the decision reads each dependency: at the ORM
boundary -- a wrapper on the connection raises ``OperationalError`` for the
statements that name a table, as a corrupt page or a statement timeout on it does
-- on the clock, on the rules, on the outcome keyring's file, on the engine's
transport, and on the stored records.
"""

from __future__ import annotations

import math
import threading
import time
from contextlib import ExitStack
from datetime import timedelta

import pytest
import requests
from django.contrib.auth import get_user_model
from django.db import OperationalError, connection
from django.utils import timezone
from mythos_core.failsafe.sign import keygen, sign_draft
from rest_framework.test import APIClient

from assurance import decision as decision_module
from assurance import observed_outcomes
from assurance import policy as policy_module
from assurance import workflow_chains
from assurance.claims import derive_claims
from assurance.decision import recompute_decision
from assurance.ingest import ingest_scan
from assurance.models import (
    ApprovedWorkflow,
    Asset,
    AssuranceClaim,
    ClaimEvent,
    ConnectorBinding,
    DataBoundary,
    DeclaredComponent,
    Deployment,
    DispatchPolicy,
    Finding,
    LatentCondition,
    PostureBinding,
    RetestRequirement,
)
from assurance.revision import read_decision
from pentest.models import Engagement, PentestScan
from pentest.views import still_authorised
from tests.signed_chains import record_signed

pytestmark = pytest.mark.django_db

User = get_user_model()
D = Deployment.Decision
Status = AssuranceClaim.ClaimStatus

#: Every stop answers within this, under every fault. A stop alone takes a few
#: milliseconds here; a stop that waited on what failed could not make it.
STOP_WITHIN_S = 1.0
#: How long an engine answering slowly takes to answer anything.
ENGINE_HANG_S = 5.0
#: The decisions a fault must never produce: deployable, with or without restrictions.
READY_FAMILY = frozenset({D.READY, D.READY_RESTRICTED})
#: A publishing read that raised rather than serve a decision.
REFUSED = "refused"

OPERATOR_PRIV, OPERATOR_PUB = keygen()
POLL_TOKEN = "p4-chaos-poll-token"
ENGINE_ID = "athena-p4-chaos"
TARGET = "https://target.example/"

# ---------------------------------------------------------------------------
# The coverage table
# ---------------------------------------------------------------------------

CLOSED = "closed"
HELD = "held"
NOT_ON_PATH = "not on path"
LEFT_OUT = "left out"
ELSEWHERE = "elsewhere"
STATUSES = (CLOSED, HELD, NOT_ON_PATH, LEFT_OUT, ELSEWHERE)

DECISION_PATHS = ("decision-support", "recompute", "receipt")
STOP_PATHS = ("pause", "revoke/contradict", "dispatch-off", "failsafe-relay", "scan-stop")
PATHS = DECISION_PATHS + STOP_PATHS

FAULTS = (
    # A read of a table the decision is computed from raises, one at a time.
    "findings-read-raises",
    "claims-read-raises",
    "retests-read-raises",
    "latent-read-raises",
    "coverage-read-raises",
    "chains-read-raises",
    # The decision's own record.
    "pause-state-unreadable",
    "decision-write-raises",
    "database-locked",
    # The rules, and the one file the decision reads.
    "policy-unreadable-or-garbage",
    "policy-changes-mid-evaluation",
    "keyring-unreadable",
    # The engine's scan signals.
    "engine-unreachable",
    "engine-answers-garbage",
    "engine-answers-slowly",
    # The composition rule the chains are read through.
    "composition-raises",
    # The stored coverage record.
    "coverage-record-corrupted",
    # The clock.
    "clock-steps-back",
    "clock-reads-nan",
    # Connector state.
    "connector-state-stale",
    # Named by the roadmap item; proven elsewhere.
    "queue-duplicates-a-job",
    "tool-succeeds-response-lost",
    "action-gate-crash",
    "minotaur-worker-dies",
)

#: What each fault is, in a line.
WHAT = {
    "findings-read-raises": "every read of the findings table raises OperationalError (disk I/O error)",
    "claims-read-raises": "every read of the assurance-claims table raises OperationalError (disk I/O error)",
    "retests-read-raises": "every read of the retest-obligations table raises OperationalError (disk I/O error)",
    "latent-read-raises": "every read of the latent-conditions table raises OperationalError (disk I/O error)",
    "coverage-read-raises": (
        "every read of the observed-asset and declared-component tables raises OperationalError "
        "(disk I/O error)"
    ),
    "chains-read-raises": (
        "every read of the approved-workflow and chain-outcome tables raises OperationalError "
        "(disk I/O error)"
    ),
    "pause-state-unreadable": (
        "every read of the decision's transition log -- where the pause in force is read "
        "from -- raises OperationalError (disk I/O error)"
    ),
    "decision-write-raises": (
        "every write of the stored decision -- an UPDATE of its columns on the deployment row, "
        "an INSERT of its transition -- raises OperationalError (disk I/O error)"
    ),
    "database-locked": (
        "every INSERT, UPDATE and DELETE raises OperationalError('database is locked'): "
        "another writer holds the write lock past the busy timeout; reads still answer"
    ),
    "policy-unreadable-or-garbage": (
        "the rules held as a document (assurance.policy.POLICY, the one copy of them kept "
        "as data) are unreadable garbage; no policy file exists to be unreadable -- the rules "
        "are module constants, read where they are applied"
    ),
    "policy-changes-mid-evaluation": (
        "a rule tightens (a low finding: ready with restrictions -> needs remediation) between "
        "an evaluation's read of its inputs and its stamp, and stays in force"
    ),
    "keyring-unreadable": "the outcome keyring's file cannot be read (it is not there)",
    "engine-unreachable": "every request to the engine is refused (ConnectionError)",
    "engine-answers-garbage": (
        "the engine's scan answer is a findings list holding nothing this side can read "
        "(rows that are not objects), ingested as a completed scan"
    ),
    "engine-answers-slowly": f"every request to the engine answers only after {ENGINE_HANG_S:.0f} s, then times out",
    "composition-raises": "the rule the workflow chains compose by raises (RuntimeError)",
    "coverage-record-corrupted": (
        "the stored check-coverage record that showed a check never ran is corrupted: every "
        "row in it is unreadable (not an object)"
    ),
    "clock-steps-back": (
        "the clock reads T+2d -- an acceptance ending at T+1d has lapsed, and the decision "
        "recorded it -- then steps back to T+12h"
    ),
    "clock-reads-nan": (
        "the float clock (time.time) reads NaN while the decision is computed. The decision's "
        "own clock is timezone.now(), a datetime, which cannot hold NaN; the float clock read "
        "NaN process-wide breaks Python's logging (LogRecord.msecs = int(NaN)) and the gateway's "
        "engine call, not the decision"
    ),
    "connector-state-stale": (
        "every ticket and posture connector's last-known state is a year old, and every "
        "fetch of a fresh one is refused"
    ),
    "queue-duplicates-a-job": "a queued job is delivered twice",
    "tool-succeeds-response-lost": "a tool's effect happens and its response is lost",
    "action-gate-crash": "the Action Gate crashes after an approval, before its receipt",
    "minotaur-worker-dies": "a Minotaur worker dies mid-campaign",
}


def _stops(**overrides: tuple[str, str]) -> dict[str, tuple[str, str]]:
    """The stop cells: each HELD -- in time, and in effect -- unless said."""
    held = {
        "pause": (HELD, "answers in time; the stored decision is paused"),
        "revoke/contradict": (
            HELD,
            "each answers in time; the claims read revoked and contradicted; the decision is recomputed",
        ),
        "dispatch-off": (HELD, "answers in time; automated dispatch is off"),
        "failsafe-relay": (HELD, "drafted and signed in time; the engine's poll serves it"),
        "scan-stop": (HELD, "answers in time; the engagement no longer authorises a scan"),
    }
    return {**held, **overrides}


#: A take-down that lands while the decision's recompute cannot read what it needs.
_HELD_TAKE_DOWN = (
    HELD,
    "each lands in time; the decision could not be recomputed, is held at needs more evidence "
    "or worse, and the answer says so (was fail-OPEN: rolled back behind a 500)",
)


def _read_raises(*, receipt=(CLOSED, "500; never READY"), **stops: tuple[str, str]):
    """A table the decision is computed from cannot be read: every decision path
    that reads it refuses, and every stop lands -- a take-down with its decision held."""
    return {
        "decision-support": (CLOSED, "500; never READY"),
        "recompute": (CLOSED, "500; nothing written; the stored decision its inputs implied stands"),
        "receipt": receipt,
        **_stops(**{"revoke/contradict": _HELD_TAKE_DOWN, **stops}),
    }


#: The receipt reads the stored decision, and not the table that failed.
_RECEIPT_READS_NONE_OF_IT = (
    NOT_ON_PATH,
    "reads none of it: serves the stored decision, which the failed recompute left as its inputs imply",
)


_INHERENT = (
    "inherent: a database that refuses every write records no stop. Answers 500 in time and "
    "claims nothing. What keeps stops landing is that nothing holds the write lock long "
    "(tests/test_nothing_that_watches_holds_back_a_stop.py); the engine's own stops -- its "
    "failsafe, its scan abort -- write nothing here"
)


def _elsewhere(where: str) -> dict[str, tuple[str, str]]:
    return {path: (ELSEWHERE, where) for path in PATHS}


MATRIX: dict[str, dict[str, tuple[str, str]]] = {
    "findings-read-raises": _read_raises(
        pause=(HELD, "answers in time; paused (was fail-OPEN: dropped behind a 500 by the finding count in its own query)"),
    )
    | {"dispatch-off": (HELD, "answers in time; dispatch off (was fail-OPEN: dropped, as the pause)")},
    "claims-read-raises": _read_raises(
        receipt=_RECEIPT_READS_NONE_OF_IT,
        **{"revoke/contradict": (
            LEFT_OUT,
            "inherent: the take-down's own claim cannot be read, so it cannot be moved -- 500 in "
            "time, nothing claimed. Every other stop is HELD under this fault; the pause is the "
            "stop that outlives it",
        )},
    ),
    "retests-read-raises": _read_raises(receipt=_RECEIPT_READS_NONE_OF_IT),
    "latent-read-raises": _read_raises(receipt=_RECEIPT_READS_NONE_OF_IT),
    "coverage-read-raises": _read_raises(
        **{"revoke/contradict": (
            HELD,
            "each lands in time; the decision could not be recomputed, is held at needs more "
            "evidence or worse, and the answer says so (was fail-OPEN: the take-down's own claim "
            "lookup joined the asset table, and a revoke dropped behind a 500 before any recompute)",
        )},
    ),
    "chains-read-raises": _read_raises(
        pause=(HELD, "answers in time; paused (was fail-OPEN: dropped behind a 500 by the chain lookup in its own query)"),
    )
    | {"dispatch-off": (HELD, "answers in time; dispatch off (was fail-OPEN: dropped, as the pause)")},
    "pause-state-unreadable": {
        "decision-support": (CLOSED, "500: a pause it cannot read is never served as no pause"),
        "recompute": (CLOSED, "500; nothing written; every publishing read refuses"),
        "receipt": (CLOSED, "500"),
        **_stops(
            pause=(
                LEFT_OUT,
                "medium: the pause numbers its move from the log it cannot read -- 500 in time, not "
                "recorded, nothing claimed. A savepoint'd read falling back to the row's own reading "
                "(the log's unique revision still guarding a row behind it) would land it, at two "
                "statements added to every stop; a fault on that table refuses its INSERT too. The "
                "failsafe relay is HELD under it",
            ),
            **{
                "revoke/contradict": (
                    LEFT_OUT,
                    "medium: each take-down lands in time (200; was fail-OPEN: rolled back behind a "
                    "500) and says the decision could be neither recomputed nor held -- both read the "
                    "log. While the log cannot be read every publishing read refuses; once it can, the "
                    "stored READY stands, stamped, beside the contradicted claim until the deployment's "
                    "next refresh. Marking it for every read to recompute needs a write of its policy "
                    "column that reads no log: a second writer of the decision columns, which "
                    "tests/test_a_stale_save_cannot_write_the_decision_back.py holds to one",
                ),
                "dispatch-off": (
                    HELD,
                    "answers in time; dispatch off (was fail-OPEN: dropped by the transition-log "
                    "read in its own query)",
                ),
            },
        ),
    },
    "decision-write-raises": {
        "decision-support": (NOT_ON_PATH, "writes nothing: serves the decision its inputs imply"),
        "recompute": (CLOSED, "500; nothing written; the stored decision its inputs implied stands"),
        "receipt": (NOT_ON_PATH, "writes nothing: serves the stored decision, which its inputs imply"),
        **_stops(
            pause=(
                LEFT_OUT,
                "inherent: the pause IS a write of the stored decision -- 500 in time, not "
                "recorded, nothing claimed. The failsafe relay and the dispatch kill switch are "
                "HELD under it",
            ),
            **{
                "revoke/contradict": (
                    LEFT_OUT,
                    "medium: each take-down lands in time (200) and says the decision could be "
                    "neither recomputed nor held; the stored READY stands, stamped, beside the "
                    "contradicted claim until the deployment's next refresh -- a take-down schedules "
                    "none. Needs a refresh that outlives the fault without holding the stop",
                )
            },
        ),
    },
    "database-locked": {
        "decision-support": (NOT_ON_PATH, "reads only: serves the decision its inputs imply"),
        "recompute": (CLOSED, "500; nothing written; the stored decision its inputs implied stands"),
        "receipt": (NOT_ON_PATH, "reads only: serves the stored decision, which its inputs imply"),
        **{path: (LEFT_OUT, _INHERENT) for path in STOP_PATHS},
    },
    "policy-unreadable-or-garbage": {
        "decision-support": (NOT_ON_PATH, "the rules are read where they are applied, never from the document"),
        "recompute": (NOT_ON_PATH, "as decision-support"),
        "receipt": (NOT_ON_PATH, "as decision-support"),
        **_stops(),
    },
    "policy-changes-mid-evaluation": {
        "decision-support": (
            CLOSED,
            "the decision the rules it read imply, naming those rules' pin (was: the pin of the "
            "rules in force after, beside a decision they did not compute)",
        ),
        "recompute": (
            CLOSED,
            "stamped with the rules it read, so every publishing read recomputes it under the "
            "rules in force: needs remediation (was fail-OPEN: ready with restrictions, stamped as "
            "the new rules')",
        ),
        "receipt": (CLOSED, "needs remediation (was fail-OPEN: ready with restrictions)"),
        **_stops(),
    },
    "keyring-unreadable": {
        "decision-support": (CLOSED, "needs more evidence: no signed chain can be shown signed"),
        "recompute": (CLOSED, "needs more evidence"),
        "receipt": (CLOSED, "needs more evidence"),
        **_stops(),
    },
    "engine-unreachable": {
        "decision-support": (
            NOT_ON_PATH,
            "the decision reads stored scan signals and asks the engine nothing; the gateway in "
            "front of every read asks /defend, and fails open",
        ),
        "recompute": (NOT_ON_PATH, "as decision-support"),
        "receipt": (NOT_ON_PATH, "as decision-support"),
        **_stops(),
    },
    "engine-answers-garbage": {
        "decision-support": (
            CLOSED,
            "not yet assessed: an answer with nothing readable in it is no report (was fail-OPEN: "
            "ready -- a clean completed scan)",
        ),
        "recompute": (CLOSED, "not yet assessed (was fail-OPEN: ready)"),
        "receipt": (CLOSED, "not yet assessed (was fail-OPEN: ready)"),
        **_stops(),
    },
    "engine-answers-slowly": {
        "decision-support": (
            NOT_ON_PATH,
            "the decision reads stored scan signals and asks the engine nothing; the gateway in "
            "front of every read asks /defend, and fails open by its deadline",
        ),
        "recompute": (NOT_ON_PATH, "as decision-support"),
        "receipt": (NOT_ON_PATH, "as decision-support"),
        **_stops(),
    },
    "composition-raises": _read_raises(),
    "coverage-record-corrupted": {
        "decision-support": (
            CLOSED,
            "audit incomplete: the unreadable rows are counted, never dropped (was fail-OPEN: ready)",
        ),
        "recompute": (CLOSED, "audit incomplete (was fail-OPEN: ready)"),
        "receipt": (CLOSED, "audit incomplete (was fail-OPEN: ready)"),
        **_stops(),
    },
    "clock-steps-back": {
        "decision-support": (
            CLOSED,
            "needs more evidence: judged no earlier than the record's last write (was fail-OPEN: "
            "ready with restrictions)",
        ),
        "recompute": (CLOSED, "needs more evidence (was fail-OPEN: ready with restrictions)"),
        "receipt": (CLOSED, "needs more evidence (was fail-OPEN: ready with restrictions)"),
        **_stops(),
    },
    "clock-reads-nan": {
        "decision-support": (
            NOT_ON_PATH,
            "the decision is computed with the float clock reading NaN and reads nothing from it: "
            "its clock is timezone.now(), a datetime",
        ),
        "recompute": (NOT_ON_PATH, "as decision-support"),
        "receipt": (NOT_ON_PATH, "as decision-support"),
        **_stops(),
    },
    "connector-state-stale": {
        "decision-support": (
            NOT_ON_PATH,
            "the decision reads no connector's state: ticket connectors are outbound only, and "
            "posture connectors fetch live and keep nothing",
        ),
        "recompute": (NOT_ON_PATH, "as decision-support"),
        "receipt": (NOT_ON_PATH, "as decision-support"),
        **_stops(),
    },
    "queue-duplicates-a-job": _elsewhere("covered by p4-idempotency (dispatch and connector duplicates)"),
    "tool-succeeds-response-lost": _elsewhere("covered by p4-idempotency (dispatch and connector duplicates)"),
    "action-gate-crash": _elsewhere("not this repository: achilles-engine, Phase 4 chaos slice 1 (#72)"),
    "minotaur-worker-dies": _elsewhere("not this repository: Minotaur"),
}


def _tested(path: str) -> list[str]:
    """The faults whose cell on ``path`` has a test: every one not LEFT_OUT or ELSEWHERE."""
    return [fault for fault in FAULTS if MATRIX[fault][path][0] not in (LEFT_OUT, ELSEWHERE)]


# ---------------------------------------------------------------------------
# The faults
# ---------------------------------------------------------------------------

#: The tables each read fault refuses to read.
READ_FAULTS = {
    "findings-read-raises": ("assurance_finding",),
    "claims-read-raises": ("assurance_assuranceclaim",),
    "retests-read-raises": ("assurance_retestrequirement",),
    "latent-read-raises": ("assurance_latentcondition",),
    "coverage-read-raises": ("assurance_asset", "assurance_declaredcomponent"),
    "chains-read-raises": ("assurance_approvedworkflow", "assurance_workflowchainoutcome"),
    "pause-state-unreadable": ("assurance_decisiontransition",),
}

#: The rules in force once the policy changes mid-evaluation: a low finding needs
#: remediation, where it was deployable with restrictions.
STRICTER_SEVERITY_DECISIONS = (
    ("critical", D.NOT_RECOMMENDED),
    ("high", D.NEEDS_REMEDIATION),
    ("low", D.NEEDS_REMEDIATION),
)


def _reads(tables):
    names = tuple(f'"{table}"' for table in tables)

    def refused(sql: str) -> bool:
        return sql.lstrip().upper().startswith("SELECT") and any(name in sql for name in names)

    return refused


def _writes_the_decision(sql: str) -> bool:
    """An INSERT of a transition, or an UPDATE of the deployment row that sets any of
    its decision columns -- every write of the stored decision there is."""
    head = sql.lstrip().upper()
    if head.startswith("INSERT"):
        return '"assurance_decisiontransition"' in sql
    if head.startswith("UPDATE") and '"assurance_deployment"' in sql.split(" SET ", 1)[0]:
        assignments = sql.split(" SET ", 1)[1].split(" WHERE ", 1)[0]
        return '"decision' in assignments
    return False


def _any_write(sql: str) -> bool:
    return sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))


class _Refusing:
    """A wrapper on the connection: every statement ``refused`` picks raises
    ``OperationalError(message)``, and every other runs."""

    def __init__(self, refused, message: str) -> None:
        self.refused = refused
        self.message = message
        self.count = 0

    def __call__(self, execute, sql, params, many, context):
        if self.refused(sql):
            self.count += 1
            raise OperationalError(self.message)
        return execute(sql, params, many, context)


def _admin():
    return User.objects.create_user(
        username=f"p4-chaos-{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    # As production answers: a raised exception is a 500, not a traceback here.
    client.raise_request_exception = False
    return client


def _body(answer) -> dict:
    try:
        body = answer.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _published(dep):
    """The stored decision as every publishing read serves it (``read_decision``),
    or REFUSED where the read raised rather than serve one."""
    try:
        return read_decision(Deployment.objects.get(pk=dep.pk))["decision"]
    except Exception:  # noqa: BLE001 - a read that refuses is an answer here, and the one asked for
        return REFUSED


def _timed(call):
    """``(seconds, result)`` of ``call()``, on ``time.monotonic``. Every fault here
    raises at once or not at all but the slow engine's, which answers only after
    ENGINE_HANG_S: a stop that asked it, or did any work it should not, shows here as
    time, and fails the bound."""
    started = time.monotonic()
    result = call()
    return time.monotonic() - started, result


class Chaos:
    """One admin, one client and the deployments a fault is asked about, with one
    fault at a time injected."""

    def __init__(self, monkeypatch, tmp_path) -> None:
        self.monkeypatch = monkeypatch
        self.tmp = tmp_path
        self.admin = _admin()
        self.client = _client(self.admin)
        self.t0 = timezone.now()
        real_now = timezone.now
        self._now = None
        # The clock every reader takes, as the tests of acceptance do: a step of it
        # is a step of the host's clock, for the decision and every stop alike.
        monkeypatch.setattr(timezone, "now", lambda: self._now if self._now is not None else real_now())
        self.fault: str | None = None
        self._stack: ExitStack | None = None
        self._patch: pytest.MonkeyPatch | None = None
        self.refusing: _Refusing | None = None
        self.engine_asked: list[str] = []
        self.float_clock_read = 0
        self._engine_release = threading.Event()

    # -- deployments ----------------------------------------------------------
    def ready(self, name: str = "ready", *, scanned: bool = True) -> Deployment:
        """A deployment on three supported claims: READY on a completed scan, or --
        not ``scanned`` -- one nothing has assessed yet."""
        dep = Deployment.objects.create(name=f"{name}-{Deployment.objects.count()}", owner=self.admin)
        if scanned:
            Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
        DataBoundary.objects.create(
            deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False,
            third_party_sharing_allowed=False,
        )
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name="tool-0", identifier="tool-0",
            classification=Asset.Classification.KNOWN,
        )
        derive_claims(Deployment.objects.get(pk=dep.pk))
        AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).update(status=Status.SUPPORTED)
        recompute_decision(Deployment.objects.get(pk=dep.pk))
        dep = Deployment.objects.get(pk=dep.pk)
        assert dep.decision == (D.READY if scanned else None), dep.decision
        return dep

    def held_back(self, fault: str) -> tuple[Deployment, str | None]:
        """A deployment whose decision the fault's dependency holds back from READY,
        and the decision its inputs imply once the fault has cleared."""
        if fault == "engine-answers-garbage":
            return self.ready(fault, scanned=False), None
        dep = self.ready(fault)
        claims = list(AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk"))
        if fault in (
            "findings-read-raises", "decision-write-raises", "database-locked", "policy-unreadable-or-garbage",
            "engine-unreachable", "engine-answers-slowly", "connector-state-stale",
        ):
            Finding.objects.create(
                deployment=dep, fingerprint="fp-p4-chaos-high", finding_type="t", title="open high",
                severity="high", status=Finding.Status.OPEN,
            )
            after = D.NEEDS_REMEDIATION
            if fault == "connector-state-stale":
                ConnectorBinding.objects.create(
                    deployment=dep, connector="jira", endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
                )
                PostureBinding.objects.create(
                    deployment=dep, domain="cloud", endpoint={"account": "acct-1", "base_url": "https://cloud.example"},
                )
        elif fault == "claims-read-raises":
            AssuranceClaim.objects.filter(pk=claims[0].pk).update(status=Status.CONTRADICTED)
            after = D.NEEDS_REMEDIATION
        elif fault == "retests-read-raises":
            RetestRequirement.objects.create(
                deployment=dep, claim=claims[0], reason="the system state moved",
                triggering_system_fingerprint="moved", opened_at=timezone.now(),
            )
            after = D.NEEDS_MORE_EVIDENCE
        elif fault == "latent-read-raises":
            LatentCondition.objects.create(
                deployment=dep, claim=claims[0], kind=LatentCondition.Kind.ASSET_APPEARS,
                subject="exporter", description="the declared precondition",
                state=LatentCondition.State.UNOBSERVABLE,
            )
            after = D.NEEDS_MORE_EVIDENCE
        elif fault == "coverage-read-raises":
            DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader")
            after = D.AUDIT_INCOMPLETE
        elif fault in ("chains-read-raises", "composition-raises"):
            ApprovedWorkflow.objects.create(deployment=dep, slug="refund", name="Refund")
            record_signed(dep, "refund", "violated", self.t0 - timedelta(minutes=5))
            after = D.NOT_RECOMMENDED
        elif fault == "pause-state-unreadable":
            recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
            after = D.PAUSED
        elif fault == "keyring-unreadable":
            ApprovedWorkflow.objects.create(deployment=dep, slug="refund", name="Refund")
            record_signed(dep, "refund", "held", self.t0 - timedelta(minutes=5), engine="athena")
            after = D.READY
        elif fault == "policy-changes-mid-evaluation":
            Finding.objects.create(
                deployment=dep, fingerprint="fp-p4-chaos-low", finding_type="t", title="open low",
                severity="low", status=Finding.Status.OPEN,
            )
            after = D.NEEDS_REMEDIATION  # under the rules in force once they have moved
        elif fault in ("clock-steps-back", "clock-reads-nan"):
            Finding.objects.create(
                deployment=dep, fingerprint="fp-p4-chaos-accepted", finding_type="t", title="accepted",
                severity="medium", status=Finding.Status.ACCEPTED,
                risk_accepted_until=self.t0 + timedelta(days=1), risk_accepted_severity="medium",
            )
            # Lapsed by the time the fault clears (the clock carries on past T+2d);
            # standing while the float clock reads NaN.
            after = D.NEEDS_MORE_EVIDENCE if fault == "clock-steps-back" else D.READY_RESTRICTED
        elif fault == "coverage-record-corrupted":
            Deployment.objects.filter(pk=dep.pk).update(
                check_coverage={
                    "checks": [
                        {"check": "xss", "state": "performed"},
                        {"check": "tls", "state": "not_performed", "reason": "cleartext target"},
                    ],
                    "unreadable": 0,
                },
                check_coverage_at=timezone.now(),
            )
            after = D.AUDIT_INCOMPLETE
        else:
            raise AssertionError(f"no such fault: {fault!r}")
        if fault != "pause-state-unreadable":
            recompute_decision(Deployment.objects.get(pk=dep.pk))
        return Deployment.objects.get(pk=dep.pk), after

    # -- the fault ------------------------------------------------------------
    def inject(self, fault: str, dep: Deployment) -> None:
        assert self.fault is None, f"{self.fault} is still injected"
        self.fault = fault
        self._stack = ExitStack()
        self._patch = patch = pytest.MonkeyPatch()
        if fault in READ_FAULTS:
            self._refuse(_reads(READ_FAULTS[fault]), "disk I/O error")
        elif fault == "decision-write-raises":
            self._refuse(_writes_the_decision, "disk I/O error")
        elif fault == "database-locked":
            self._refuse(_any_write, "database is locked")
        elif fault == "policy-unreadable-or-garbage":
            patch.setattr(policy_module, "POLICY", b"\x00\xff{ this is not a policy")
        elif fault == "policy-changes-mid-evaluation":
            real, moved = decision_module.read_decision_parts, []

            def read_then_the_rules_move(*args, **kwargs):
                parts = real(*args, **kwargs)
                if not moved:
                    moved.append(True)
                    # Into the test's own patch: the new rules stay in force once the
                    # fault clears, as a policy change does.
                    self.monkeypatch.setattr(
                        decision_module, "FINDING_SEVERITY_DECISIONS", STRICTER_SEVERITY_DECISIONS
                    )
                return parts

            patch.setattr(decision_module, "read_decision_parts", read_then_the_rules_move)
        elif fault == "keyring-unreadable":
            patch.setenv(observed_outcomes.KEYRING_ENV, str(self.tmp / "no-such-dir" / "keyring.json"))
        elif fault in ("engine-unreachable", "engine-answers-slowly", "connector-state-stale"):
            self._engine(patch, slow=fault == "engine-answers-slowly")
            if fault == "connector-state-stale":
                a_year_ago = self.t0 - timedelta(days=365)
                ConnectorBinding.objects.filter(deployment=dep).update(updated_at=a_year_ago)
                PostureBinding.objects.filter(deployment=dep).update(updated_at=a_year_ago)
        elif fault == "engine-answers-garbage":
            scan = PentestScan.objects.create(
                user=self.admin, target_url=TARGET, consent=True, status=PentestScan.STATUS_COMPLETED,
                engine_response={"findings": ["not a finding", 7, None]},
            )
            ingest_scan(scan, deployment=Deployment.objects.get(pk=dep.pk))
        elif fault == "composition-raises":

            def compose(*args, **kwargs):
                raise RuntimeError("the composition rule failed")

            patch.setattr(workflow_chains, "compose", compose)
        elif fault == "coverage-record-corrupted":
            # As a data migration, a fixture load or a shell would write it: a
            # QuerySet update, which recomputes nothing.
            Deployment.objects.filter(pk=dep.pk).update(check_coverage={"checks": ["xss", "tls"], "unreadable": 0})
        elif fault == "clock-steps-back":
            # The service reads T+2d first -- a publishing read, which recomputes
            # the decision a lapse moved -- and then the clock steps back.
            self._now = self.t0 + timedelta(days=2)
            recorded = read_decision(Deployment.objects.get(pk=dep.pk))["decision"]
            if Finding.objects.filter(deployment=dep, status=Finding.Status.ACCEPTED).exists():
                assert recorded == D.NEEDS_MORE_EVIDENCE, f"the lapse was not recorded: {recorded}"
            self._now = self.t0 + timedelta(hours=12)
        elif fault == "clock-reads-nan":
            self._float_clock_nan_while_deciding(patch)
        else:
            raise AssertionError(f"no such fault: {fault!r}")

    def _float_clock_nan_while_deciding(self, patch: pytest.MonkeyPatch) -> None:
        """While the decision is computed -- its inputs read, the rule applied, a
        stored decision reconciled -- the float clock reads NaN, and every reading of
        it is counted. Outside, it reads the time: read NaN process-wide it breaks
        Python's logging, which is not the decision."""
        real_time, inside = time.time, []

        def float_clock():
            if inside:
                self.float_clock_read += 1
                return math.nan
            return real_time()

        def deciding(real):
            def run(*args, **kwargs):
                inside.append(True)
                try:
                    return real(*args, **kwargs)
                finally:
                    inside.pop()

            return run

        patch.setattr(time, "time", float_clock)
        for name in ("read_decision_parts", "decide", "current_decision", "decision_now"):
            if hasattr(decision_module, name):  # decision_now is this slice's
                patch.setattr(decision_module, name, deciding(getattr(decision_module, name)))

    def _refuse(self, refused, message: str) -> None:
        self.refusing = _Refusing(refused, message)
        self._stack.enter_context(connection.execute_wrapper(self.refusing))

    def _engine(self, patch: pytest.MonkeyPatch, *, slow: bool) -> None:
        """Every request through ``requests`` -- the engine client's transport, and a
        posture connector's -- refused, or answered only after ENGINE_HANG_S."""
        self._engine_release.clear()

        def request(session, method, url, *args, **kwargs):
            self.engine_asked.append(f"{method} {url}")
            if slow:
                self._engine_release.wait(ENGINE_HANG_S)
                raise requests.Timeout(f"no answer from {url} in {ENGINE_HANG_S} s")
            raise requests.ConnectionError(f"{url}: connection refused")

        patch.setattr(requests.sessions.Session, "request", request)

    def clear(self) -> None:
        """Take the fault off. A clock that stepped back carries on from past the
        latest reading it went behind; a corrupted record, an ingested answer and a
        moved rule stay -- they are what the fault left, not the fault."""
        fault, self.fault = self.fault, None
        self._engine_release.set()
        if self._stack is not None:
            self._stack.close()
            self._stack = None
        if self._patch is not None:
            self._patch.undo()
            self._patch = None
        self.refusing = None
        if fault == "clock-steps-back":
            self._now = self.t0 + timedelta(days=2, seconds=1)

    def close(self) -> None:
        if self.fault is not None:
            self.clear()
        self._engine_release.set()
        self._now = None

    # -- decision paths -------------------------------------------------------
    def support(self, dep):
        return self.client.get(f"/api/assurance/deployments/{dep.uuid}/decision-support/")

    def recompute(self, dep):
        return self.client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json")

    def receipt(self, dep):
        return self.client.get(f"/api/assurance/deployments/{dep.uuid}/assurance-receipt/")

    # -- stops ----------------------------------------------------------------
    def pause(self, dep):
        return self.client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")

    def transition(self, claim, to_status):
        return self.client.post(f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": to_status}, format="json")

    def dispatch_off(self, dep):
        return self.client.put(f"/api/assurance/deployments/{dep.uuid}/dispatch-policy/", {"enabled": False}, format="json")

    def draft(self):
        return self.client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": ENGINE_ID}, format="json")

    def sign(self, drafted: dict):
        fields = {k: drafted[k] for k in ("action", "engine_id", "nonce", "issued_at", "expires_at", "reason")}
        signature = sign_draft(fields, key_id="operator", private_hex=OPERATOR_PRIV)
        return self.client.post(f"/api/failsafe/commands/{drafted['uuid']}/signatures/", signature, format="json")

    def polled(self) -> list:
        answer = APIClient().get("/api/failsafe/pending/", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)
        assert answer.status_code == 200, answer.content
        return answer.json()

    def scan_stop(self, engagement):
        return self.client.patch(f"/api/pentest/engagements/{engagement.pk}/", {"status": "paused"}, format="json")


@pytest.fixture
def chaos(monkeypatch, tmp_path, settings, engine_keyring):
    settings.FAILSAFE_OPERATOR_KEYS = {"operator": OPERATOR_PUB}
    settings.FAILSAFE_POLL_TOKEN = POLL_TOKEN
    settings.FAILSAFE_COMMAND_TTL_SECONDS = 600
    world = Chaos(monkeypatch, tmp_path)
    try:
        yield world
    finally:
        world.close()


# ---------------------------------------------------------------------------
# The table's completeness
# ---------------------------------------------------------------------------


def test_the_matrix_names_every_cell():
    """Every fault has a cell on every path, and every cell says what it shows. A
    cell is never simply absent: one this suite does not prove is LEFT_OUT, with
    its repro and its severity, or ELSEWHERE, naming where."""
    assert set(MATRIX) == set(FAULTS) == set(WHAT)
    for fault in FAULTS:
        assert set(MATRIX[fault]) == set(PATHS), fault
        for path, (status, shows) in MATRIX[fault].items():
            assert status in STATUSES, (fault, path, status)
            assert shows.strip(), (fault, path)
            if path in STOP_PATHS:
                assert status in (HELD, LEFT_OUT, ELSEWHERE), (fault, path, status)
            else:
                assert status in (CLOSED, NOT_ON_PATH, LEFT_OUT, ELSEWHERE), (fault, path, status)
    for path, table in (("decision-support", SUPPORT), ("recompute", RECOMPUTE), ("receipt", RECEIPT)):
        assert set(table) == set(_tested(path)), path
    assert set(TAKE_DOWN) == set(_tested("revoke/contradict"))


# ---------------------------------------------------------------------------
# decision paths: never READY on a fault that hid what the decision needs
# ---------------------------------------------------------------------------

#: What each tested cell answers: (status code, the decision it serves -- None for
#: a deployment nothing has assessed; ignored for a 5xx).
SUPPORT = {
    "findings-read-raises": (500, None),
    "claims-read-raises": (500, None),
    "retests-read-raises": (500, None),
    "latent-read-raises": (500, None),
    "coverage-read-raises": (500, None),
    "chains-read-raises": (500, None),
    "pause-state-unreadable": (500, None),
    "decision-write-raises": (200, D.NEEDS_REMEDIATION),
    "database-locked": (200, D.NEEDS_REMEDIATION),
    "policy-unreadable-or-garbage": (200, D.NEEDS_REMEDIATION),
    # The rules it read imply this, and it names them (NAMES_ITS_RULES).
    "policy-changes-mid-evaluation": (200, D.READY_RESTRICTED),
    "keyring-unreadable": (200, D.NEEDS_MORE_EVIDENCE),
    "engine-unreachable": (200, D.NEEDS_REMEDIATION),
    "engine-answers-garbage": (200, None),
    "engine-answers-slowly": (200, D.NEEDS_REMEDIATION),
    "composition-raises": (500, None),
    "coverage-record-corrupted": (200, D.AUDIT_INCOMPLETE),
    "clock-steps-back": (200, D.NEEDS_MORE_EVIDENCE),
    "clock-reads-nan": (200, D.READY_RESTRICTED),
    "connector-state-stale": (200, D.NEEDS_REMEDIATION),
}
#: Each tested cell: (the recompute's status code, the stored decision as every
#: publishing read then serves it under the fault -- REFUSED for a read that raises).
RECOMPUTE = {
    "findings-read-raises": (500, D.NEEDS_REMEDIATION),
    "claims-read-raises": (500, D.NEEDS_REMEDIATION),
    "retests-read-raises": (500, D.NEEDS_MORE_EVIDENCE),
    "latent-read-raises": (500, D.NEEDS_MORE_EVIDENCE),
    "coverage-read-raises": (500, D.AUDIT_INCOMPLETE),
    "chains-read-raises": (500, D.NOT_RECOMMENDED),
    "pause-state-unreadable": (500, REFUSED),
    "decision-write-raises": (500, D.NEEDS_REMEDIATION),
    "database-locked": (500, D.NEEDS_REMEDIATION),
    "policy-unreadable-or-garbage": (200, D.NEEDS_REMEDIATION),
    "policy-changes-mid-evaluation": (200, D.NEEDS_REMEDIATION),
    "keyring-unreadable": (200, D.NEEDS_MORE_EVIDENCE),
    "engine-unreachable": (200, D.NEEDS_REMEDIATION),
    "engine-answers-garbage": (200, None),
    "engine-answers-slowly": (200, D.NEEDS_REMEDIATION),
    "composition-raises": (500, D.NOT_RECOMMENDED),
    "coverage-record-corrupted": (200, D.AUDIT_INCOMPLETE),
    "clock-steps-back": (200, D.NEEDS_MORE_EVIDENCE),
    "clock-reads-nan": (200, D.READY_RESTRICTED),
    "connector-state-stale": (200, D.NEEDS_REMEDIATION),
}
RECEIPT = {
    "findings-read-raises": (500, None),
    "claims-read-raises": (200, D.NEEDS_REMEDIATION),
    "retests-read-raises": (200, D.NEEDS_MORE_EVIDENCE),
    "latent-read-raises": (200, D.NEEDS_MORE_EVIDENCE),
    "coverage-read-raises": (500, None),
    "chains-read-raises": (500, None),
    "pause-state-unreadable": (500, None),
    "decision-write-raises": (200, D.NEEDS_REMEDIATION),
    "database-locked": (200, D.NEEDS_REMEDIATION),
    "policy-unreadable-or-garbage": (200, D.NEEDS_REMEDIATION),
    "policy-changes-mid-evaluation": (200, D.NEEDS_REMEDIATION),
    "keyring-unreadable": (200, D.NEEDS_MORE_EVIDENCE),
    "engine-unreachable": (200, D.NEEDS_REMEDIATION),
    "engine-answers-garbage": (200, None),
    "engine-answers-slowly": (200, D.NEEDS_REMEDIATION),
    "composition-raises": (500, None),
    "coverage-record-corrupted": (200, D.AUDIT_INCOMPLETE),
    "clock-steps-back": (200, D.NEEDS_MORE_EVIDENCE),
    "clock-reads-nan": (200, D.READY_RESTRICTED),
    "connector-state-stale": (200, D.NEEDS_REMEDIATION),
}
#: A live answer computed under rules that moved while it read: it serves what the
#: rules it read imply, and names those rules -- never the ones in force after.
NAMES_ITS_RULES = frozenset({"policy-changes-mid-evaluation"})
#: The faults under which the decision may ask the engine nothing. The gateway in front
#: of every request that is not a stop (audit.middleware) asks the engine's /defend,
#: and fails open; that is its call, not the decision's.
ENGINE_FAULTS = frozenset({"engine-unreachable", "engine-answers-slowly", "connector-state-stale"})


def _asked_only_by_the_gateway(fault: str, path: str, asked: list[str]) -> None:
    beyond = [call for call in asked if not call.endswith("/defend")]
    assert beyond == [], f"{fault}: {path} asked the engine: {beyond}"


def _never_ready(fault: str, path: str, served) -> None:
    """A CLOSED cell never serves READY or READY_RESTRICTED. (A NOT_ON_PATH cell
    serves what it would anyway, which its own table pins.)"""
    if MATRIX[fault][path][0] == CLOSED and not (path == "decision-support" and fault in NAMES_ITS_RULES):
        assert served not in READY_FAMILY, f"{fault}: {path} served {served}"


def _after_the_fault(chaos, dep, after) -> None:
    """Once the fault clears, every surface reads what the inputs imply: nothing the
    fault did was left behind -- no stale READY, no decision the inputs do not
    support."""
    live = chaos.support(dep)
    assert live.status_code == 200, live.content
    assert live.json()["decision"] == after, live.json()
    assert _published(dep) == after


@pytest.mark.parametrize("fault", _tested("decision-support"))
def test_no_fault_serves_a_ready_decision(fault, chaos):
    dep, after = chaos.held_back(fault)
    pin = policy_module.policy_pin()
    chaos.inject(fault, dep)
    try:
        answer = chaos.support(dep)
    finally:
        chaos.clear()
    status, decision = SUPPORT[fault]
    body = _body(answer)
    _never_ready(fault, "decision-support", body.get("decision") if answer.status_code == 200 else None)
    assert answer.status_code == status, answer.content[:600]
    if status == 200:
        assert body["decision"] == decision, body
    if fault in NAMES_ITS_RULES:
        assert body["policy_version"] == pin, f"{fault}: served under {body['policy_version']}, computed under {pin}"
    if fault in ENGINE_FAULTS:
        _asked_only_by_the_gateway(fault, "decision-support", chaos.engine_asked)
    if fault == "clock-reads-nan":
        assert chaos.float_clock_read == 0, "the decision read the float clock"
    _after_the_fault(chaos, dep, after)


@pytest.mark.parametrize("fault", _tested("recompute"))
def test_no_fault_writes_a_ready_decision(fault, chaos):
    dep, after = chaos.held_back(fault)
    chaos.inject(fault, dep)
    try:
        answer = chaos.recompute(dep)
        published = _published(dep)
    finally:
        chaos.clear()
    status, expected = RECOMPUTE[fault]
    _never_ready(fault, "recompute", published)
    assert answer.status_code == status, answer.content[:600]
    assert published == expected, f"{fault}: every publishing read serves {published}"
    if fault in ENGINE_FAULTS:
        _asked_only_by_the_gateway(fault, "the recompute", chaos.engine_asked)
    if fault == "clock-reads-nan":
        assert chaos.float_clock_read == 0, "the decision read the float clock"
    _after_the_fault(chaos, dep, after)


@pytest.mark.parametrize("fault", _tested("receipt"))
def test_no_fault_leaves_a_ready_receipt(fault, chaos):
    dep, after = chaos.held_back(fault)
    chaos.inject(fault, dep)
    try:
        chaos.recompute(dep)  # a write moved an input: the stored decision is recomputed
        answer = chaos.receipt(dep)
    finally:
        chaos.clear()
    status, decision = RECEIPT[fault]
    served = (_body(answer).get("result") or {}).get("decision") if answer.status_code == 200 else None
    _never_ready(fault, "receipt", served)
    assert answer.status_code == status, answer.content[:600]
    if status == 200:
        assert served == decision, _body(answer).get("result")
    if fault in ENGINE_FAULTS:
        _asked_only_by_the_gateway(fault, "the receipt", chaos.engine_asked)
    if fault == "clock-reads-nan":
        assert chaos.float_clock_read == 0, "the decision read the float clock"
    _after_the_fault(chaos, dep, after)


# ---------------------------------------------------------------------------
# stops: in time, against a bound, and in effect
# ---------------------------------------------------------------------------


def _stop_on(chaos, fault):
    """The READY deployment a stop is made on, with any fault that lives in the
    record written into it."""
    dep = chaos.ready()
    if fault == "connector-state-stale":
        ConnectorBinding.objects.create(deployment=dep, connector="jira", endpoint={"base_url": "https://jira.example"})
        PostureBinding.objects.create(deployment=dep, domain="cloud", endpoint={"base_url": "https://cloud.example"})
    return dep


@pytest.mark.parametrize("fault", _tested("pause"))
def test_no_fault_holds_a_pause(fault, chaos):
    dep = _stop_on(chaos, fault)
    chaos.inject(fault, dep)
    try:
        took, answer = _timed(lambda: chaos.pause(dep))
    finally:
        chaos.clear()
    stored = Deployment.objects.get(pk=dep.pk).decision
    assert stored == D.PAUSED, f"{fault}: the pause did not land: the stored decision reads {stored} ({answer.status_code})"
    assert took < STOP_WITHIN_S, f"{fault}: the pause took {took:.3f}s"
    assert answer.status_code == 200, f"{fault}: the pause answered {answer.status_code}: {answer.content[:300]}"
    assert answer.json()["decision"] == D.PAUSED, answer.json()


#: What each take-down's answer says of the decision it moved, per fault:
#: ("recomputed", None), or ("held", the words naming what the recompute met) -- held
#: where no recompute reached it (decision.hold_unrecomputed).
TAKE_DOWN = {
    "findings-read-raises": ("held", "could not be recomputed (OperationalError)"),
    "retests-read-raises": ("held", "could not be recomputed (OperationalError)"),
    "latent-read-raises": ("held", "could not be recomputed (OperationalError)"),
    "coverage-read-raises": ("held", "could not be recomputed (OperationalError)"),
    "chains-read-raises": ("held", "could not be recomputed (OperationalError)"),
    "policy-unreadable-or-garbage": ("recomputed", None),
    "policy-changes-mid-evaluation": ("recomputed", None),
    "keyring-unreadable": ("recomputed", None),
    "engine-unreachable": ("recomputed", None),
    "engine-answers-garbage": ("recomputed", None),
    "engine-answers-slowly": ("recomputed", None),
    "composition-raises": ("held", "could not be recomputed (RuntimeError)"),
    "coverage-record-corrupted": ("recomputed", None),
    "clock-steps-back": ("recomputed", None),
    "clock-reads-nan": ("recomputed", None),
    "connector-state-stale": ("recomputed", None),
}


@pytest.mark.parametrize("fault", _tested("revoke/contradict"))
def test_no_fault_holds_a_revoke_or_a_contradiction(fault, chaos):
    dep = _stop_on(chaos, fault)
    revoked, contradicted = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk")[:2]
    chaos.inject(fault, dep)
    try:
        revoke_took, revoke = _timed(lambda: chaos.transition(revoked, "revoked"))
        contradict_took, contradict = _timed(lambda: chaos.transition(contradicted, "contradicted"))
        published_under_fault = _published(dep)
    finally:
        chaos.clear()
    # In effect: both claims are down, whatever the decision could read.
    for what, claim, answer, down in (
        ("revoke", revoked, revoke, Status.REVOKED), ("contradiction", contradicted, contradict, Status.CONTRADICTED)
    ):
        reads = AssuranceClaim.objects.get(pk=claim.pk).status
        assert reads == down, f"{fault}: the {what} did not land: the claim reads {reads} ({answer.status_code})"
    for what, took, answer in (("revoke", revoke_took, revoke), ("contradiction", contradict_took, contradict)):
        assert took < STOP_WITHIN_S, f"{fault}: the {what} took {took:.3f}s"
        assert answer.status_code == 200, f"{fault}: the {what} answered {answer.status_code}: {answer.content[:300]}"
    # Each answer says what became of the decision: recomputed, or held -- never
    # READY -- naming what the recompute met.
    left, words = TAKE_DOWN[fault]
    for what, answer in (("revoke", revoke), ("contradiction", contradict)):
        body = answer.json()
        assert body["decision_recomputed"] is (left == "recomputed"), (what, body)
        if left == "held":
            assert body["decision"] is not None and body["decision"] not in READY_FAMILY, (what, body)
        if words is not None:
            assert words in body["decision_unrecomputed"], (what, body)
    # And no publishing read serves READY beside the contradicted claim.
    assert published_under_fault not in READY_FAMILY, f"{fault}: {published_under_fault} published beside a contradicted claim"
    # Once the fault clears, the first publishing read reads what the claims imply.
    assert _published(dep) == D.NEEDS_REMEDIATION


@pytest.mark.parametrize("fault", _tested("dispatch-off"))
def test_no_fault_holds_the_dispatch_kill_switch(fault, chaos):
    dep = _stop_on(chaos, fault)
    DispatchPolicy.objects.create(deployment=dep, enabled=True, created_by=chaos.admin)
    chaos.inject(fault, dep)
    try:
        took, answer = _timed(lambda: chaos.dispatch_off(dep))
    finally:
        chaos.clear()
    enabled = DispatchPolicy.objects.get(deployment=dep).enabled
    assert enabled is False, f"{fault}: dispatch-off did not land: automated dispatch is still on ({answer.status_code})"
    assert took < STOP_WITHIN_S, f"{fault}: switching dispatch off took {took:.3f}s"
    assert answer.status_code == 200, f"{fault}: dispatch-off answered {answer.status_code}: {answer.content[:300]}"


@pytest.mark.parametrize("fault", _tested("failsafe-relay"))
def test_no_fault_holds_the_failsafe_relay(fault, chaos):
    dep = _stop_on(chaos, fault)  # a deployment on record, as there always is
    chaos.inject(fault, dep)
    try:
        drafted_in, drafted = _timed(chaos.draft)
        assert drafted.status_code == 201, f"{fault}: the draft answered {drafted.status_code}: {drafted.content[:300]}"
        signed_in, signed = _timed(lambda: chaos.sign(drafted.json()))
        # In effect: the engine's poll, made under the same fault, serves the signed pause.
        served = [command["nonce"] for command in chaos.polled()]
    finally:
        chaos.clear()
    assert drafted_in < STOP_WITHIN_S, f"{fault}: the draft took {drafted_in:.3f}s"
    assert signed_in < STOP_WITHIN_S, f"{fault}: the signature took {signed_in:.3f}s"
    assert signed.status_code == 200, f"{fault}: the signature answered {signed.status_code}: {signed.content[:300]}"
    assert signed.json()["status"] == "ready", signed.json()
    assert drafted.json()["nonce"] in served, f"{fault}: the engine's poll did not serve the signed pause"


@pytest.mark.parametrize("fault", _tested("scan-stop"))
def test_no_fault_holds_a_scan_stop(fault, chaos):
    engagement = Engagement.objects.create(
        name="p4-chaos", created_by=chaos.admin, status="running", scope_hosts=["target.example"],
        testing_window_start=chaos.t0 - timedelta(days=1), testing_window_end=chaos.t0 + timedelta(days=30),
    )
    assert still_authorised(engagement, TARGET)
    chaos.inject(fault, _stop_on(chaos, fault))
    try:
        took, answer = _timed(lambda: chaos.scan_stop(engagement))
    finally:
        chaos.clear()
    engagement.refresh_from_db()
    assert engagement.status == "paused", f"{fault}: the scan stop did not land ({answer.status_code})"
    assert took < STOP_WITHIN_S, f"{fault}: the scan stop took {took:.3f}s"
    assert answer.status_code == 200, f"{fault}: the scan stop answered {answer.status_code}: {answer.content[:300]}"
    assert not still_authorised(engagement, TARGET)


# ---------------------------------------------------------------------------
# A take-down whose transaction the database ends is made again
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_a_take_down_whose_transaction_the_database_ends_is_made_again(monkeypatch, tmp_path, settings, engine_keyring):
    """SQLite rolls a whole transaction back on some I/O, full-disk and busy errors,
    and the savepoint the recompute ran in goes with it: rolling back to it fails.
    Carried on, the take-down would be answered 200 and never committed -- a record of
    a stop that did not happen. It is made again, in a transaction of its own, with
    the decision held rather than recomputed: once, and landed."""
    world = Chaos(monkeypatch, tmp_path)
    try:
        dep = world.ready()
        claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
        lost = []

        def refused(sql: str) -> bool:
            if _reads(READ_FAULTS["findings-read-raises"])(sql):
                return True
            # The database already ended the transaction the savepoint was in.
            if sql.lstrip().upper().startswith("ROLLBACK TO SAVEPOINT") and not lost:
                lost.append(sql)
                return True
            return False

        with connection.execute_wrapper(_Refusing(refused, "disk I/O error")):
            took, answer = _timed(lambda: world.transition(claim, "revoked"))
    finally:
        world.close()
    assert lost, "the savepoint the recompute ran in was never rolled back to"
    assert took < STOP_WITHIN_S, f"the take-down took {took:.3f}s"
    assert answer.status_code == 200, answer.content[:600]
    body = answer.json()
    assert body["status"] == Status.REVOKED
    assert body["decision_recomputed"] is False and body["decision"] == D.NEEDS_MORE_EVIDENCE, body
    assert AssuranceClaim.objects.get(pk=claim.pk).status == Status.REVOKED
    # Made once: the first attempt's writes went with its transaction.
    assert ClaimEvent.objects.filter(claim=claim, to_status=Status.REVOKED).count() == 1
    assert Deployment.objects.get(pk=dep.pk).decision == D.NEEDS_MORE_EVIDENCE
