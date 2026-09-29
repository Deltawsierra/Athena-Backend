"""Firing the same operation twice makes ONE external effect and ONE Claim (Phase 4).

Roadmap Phase 4, "Duplicate-execution and idempotency protection": a duplicated job
or a retried tool call must not produce two external effects or two conflicting
Claims. Every boundary where this backend changes something elsewhere -- an
outbound call, or a durable row another process acts on -- is fired twice here, the
way it is fired twice in practice: a replayed request, a duplicated due row or queue
message, a retry after a lost acknowledgement. Every external effect is counted on a
fake transport; nothing here reaches the network (:func:`engine` answers every HTTP
call this process makes).

:data:`MATRIX` names each boundary, the key it deduplicates on before this change and
after it, what firing it twice does, and the tests that prove it.
:func:`test_every_effect_boundary_in_the_code_is_in_the_matrix` reads the code and
fails on a call site that makes an external effect -- ``requests`` writing, an
e-mail, a connector push, an engine call that POSTs, a durable row another process
acts on -- that :data:`SITES` does not name, so a new boundary cannot land without a
row here and its fire-twice test.

A STOP IS NEVER DEDUPLICATED. A pause, revoke, contradiction, stand-down, terminate,
an engagement's authority withdrawn, an operator demoted or removed is processed every
time it arrives, with an ``Idempotency-Key`` or without one: the key layer is never on
a stop route (safety.stops, the SAFETY RULE), and the tests at the end prove a stop
replayed with a key still executes.
"""

from __future__ import annotations

import ast
import copy
import io
import json
import os
import uuid
from collections import namedtuple
from datetime import timedelta
from pathlib import Path
from unittest import mock

import pytest
import requests
import requests.exceptions as rex
import urllib3
from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.db import connection
from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext
from django.urls import get_resolver
from django.utils import timezone
from rest_framework.test import APIClient

from ai_engine.services import preflight
from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError
from assurance import dispatch
from assurance.claims import derive_claims
from assurance.connectors import RequestsTransport
from assurance.evidence_audit import EvidenceRefused, invalidate_claim_evidence, record_claim_evidence
from assurance.ingest import ingest_scan
from assurance.invalidation import check_invalidations
from assurance.models import (
    Asset,
    AssuranceClaim,
    ClaimEvent,
    ClaimEvidence,
    ClaimVerdict,
    ConnectorBinding,
    DecisionDispatchDue,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    EvidenceClass,
    Finding,
    RetestRequirement,
)
from assurance.served_route import serving_route_now
from audit.middleware import DefenderMiddleware
from failsafe.models import FailsafeCommand
from pentest.models import Engagement, PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
ClaimStatus = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType

REPO = Path(__file__).resolve().parent.parent
KEY = "HTTP_IDEMPOTENCY_KEY"

# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------

Boundary = namedtuple("Boundary", "what key_before key_after twice tests")

_KEY_LAYER = (
    "Idempotency-Key header: (account, route, key) + a digest of the request -> the answer "
    "recorded (idempotency.layer); kept IDEMPOTENCY_KEY_TTL_SECONDS, at most "
    "IDEMPOTENCY_KEYS_PER_ACCOUNT per account"
)

#: Every effect boundary in this backend. ``tests`` are the fire-twice tests in this
#: module that hold it; :func:`test_every_matrix_test_exists` keeps the names honest.
MATRIX = {
    "engine-scan-start": Boundary(
        "POST /api/pentest/scan/: a PentestScan row, then the engine's POST /api/scan -- a scan "
        "of the customer's live system -- and the report e-mailed; and POST "
        "/api/pentest/scans/<uuid>/reconcile/, which sends a launch whose answer was lost again",
        "none: every request made a row and started an engine scan",
        _KEY_LAYER + "; and every engine launch of a scan carries the scan's own Idempotency-Key "
        "(PentestScan.launch_key), which athena-engine #77 answers once",
        "with the key: one row, one engine scan, one e-mail; the replay answers what the first "
        "was answered (Idempotent-Replayed). Without a key: unchanged -- a retry scans again. A "
        "launch whose engine answer was lost is UNKNOWN, and a reconcile sent again and again "
        "adopts the first launch's run: one engine scan",
        (
            "test_a_scan_launch_replayed_with_its_key_starts_one_engine_scan",
            "test_a_scan_launch_whose_engine_answer_was_lost_is_not_launched_again_by_its_replay",
            "test_a_lost_launch_reconciled_again_and_again_scans_the_customer_once",
            "test_a_scan_replayed_after_its_engagement_was_withdrawn_starts_nothing",
            "test_a_scan_replayed_by_an_account_demoted_since_is_refused_before_any_record",
            "test_the_same_key_with_another_request_is_refused_and_starts_nothing",
            "test_a_replay_while_the_first_is_still_running_is_refused_and_starts_nothing",
            "test_a_launch_that_raised_before_it_recorded_an_answer_reads_as_unknown",
            "test_a_scan_launch_without_a_key_is_unchanged_and_its_retry_scans_again",
        ),
    ),
    "engine-scan-stop": Boundary(
        "A scan's Stop: the engine's POST /api/scans/{run_id}/abort for exactly the scan's run -- "
        "from POST /api/pentest/scans/<uuid>/stop/, from a launch or reconcile that names the run a "
        "Stop is owed on, and from manage.py deliver_owed_stops",
        "none: no scan Stop existed",
        "none: a stop is never deduplicated (safety.stops); the engine's abort of one run by its id "
        "is safe to send again, and carries no Idempotency-Key",
        "each Stop sends the abort for that run again, and only for that run: never abort-all",
        ("test_a_scan_stop_sent_twice_is_sent_to_its_run_each_time",),
    ),
    "engine-llm-scan-start": Boundary(
        "POST /api/pentest/llm-scan/: a PentestScan row, then the engine's POST /api/llm-scan -- a "
        "red-team run against the customer's model -- and the report e-mailed",
        "none: every request made a row and started an engine run",
        _KEY_LAYER,
        "with the key: one row, one engine run; without: unchanged",
        ("test_an_llm_scan_launch_replayed_with_its_key_starts_one_engine_run",),
    ),
    "llm-scan-view-unrouted": Boundary(
        "pentest.views_llm.PentestLLMScanView: an engine LLM run and a row, in a view no URL names",
        "none", "none (unreachable)",
        "cannot be fired: no route reaches it",
        ("test_the_unrouted_llm_scan_view_is_reachable_by_no_url",),
    ),
    "report-email": Boundary(
        "The scan report e-mailed (pentest.utils.send_pentest_scan_email): once by a scan launch, "
        "again by POST /api/pentest/scans/<uuid>/email/",
        "none: every resend request sent the report",
        _KEY_LAYER + " on the launch routes and the resend route",
        "with the key: one e-mail; without: unchanged -- a retried resend sends it again",
        (
            "test_a_report_resend_replayed_with_its_key_sends_one_email",
            "test_an_account_keeps_at_most_its_bound_of_keys",
        ),
    ),
    "connector-push-manual": Boundary(
        "POST /api/assurance/deployments/<uuid>/connectors/<name>/push/: a person files a finding "
        "in the customer's tracker; no DispatchAttempt, no look first, no operation id",
        "none: every request filed a ticket",
        _KEY_LAYER,
        "with the key: one ticket, and the replay answers its ConnectorResult; without: unchanged",
        ("test_a_manual_connector_push_replayed_with_its_key_files_one_ticket",),
    ),
    "connector-push-dispatch": Boundary(
        "Automated dispatch (assurance.dispatch): a finding pushed to a bound connector, a comment "
        "on a closed issue, over RequestsTransport",
        "DispatchAttempt unique (finding, connector) -- SENT is terminal; SENDING recorded before "
        "the request; an uncertain attempt is looked for by its marker before anything is sent; "
        "the operation id in Idempotency-Key where the receiver dedupes (webhook)",
        "unchanged",
        "one ticket, however many triggers; a lost answer is found by its marker, not filed again; "
        "a webhook redelivery carries the same Idempotency-Key",
        (
            "test_a_finding_dispatched_twice_files_one_ticket",
            "test_a_dispatch_whose_answer_was_lost_is_found_not_filed_again",
            "test_a_webhook_redelivery_carries_the_same_operation_id",
        ),
    ),
    "webhook-receipt-push": Boundary(
        "WebhookConnector.push_receipt: an assurance receipt forwarded to a webhook",
        "none", "none (nothing calls it)",
        "cannot be fired: no caller",
        ("test_the_webhook_receipt_push_has_no_caller",),
    ),
    "decision-dispatch-owed": Boundary(
        "DecisionDispatchDue: the dispatch a pause (a stop) owes, run by the stop's thread, every "
        "process's sweeper and manage.py retry_blocking_dispatches",
        "one row per deployment (OneToOne), a request counter, a run claim (run_token)",
        "unchanged",
        "each pause is processed (a stop); the owed dispatch is one row, and it files one ticket "
        "however many runners run it",
        ("test_a_pause_replayed_owes_one_dispatch_and_files_one_ticket",),
    ),
    "engine-transport": Boundary(
        "The engine client's POST (CyberEngineClient._send_post, .defend_log_file) and the connector "
        "transport's (RequestsTransport.post): the calls every engine and tracker write goes through",
        "none needed: each sends its request once", "unchanged",
        "one request per call, a lost answer included: nothing re-sends on its own",
        ("test_the_transports_send_a_request_once_even_when_its_answer_is_lost",),
    ),
    "engine-analysis": Boundary(
        "Text and CVE analysis (detection routes -> engine /api/defend-log/text, /api/classify-cve): "
        "a question to the engine, and its answer kept here; no effect elsewhere",
        "none", "none: not an effect",
        "each request asks once; a replay asks again and changes nothing outside this backend",
        ("test_an_analysis_asks_the_engine_once_per_request",),
    ),
    "engine-governance": Boundary(
        "The engine's governance calls: the preflight gate's /api/assurance/check and "
        "/api/attestation/check, approve_deployment's /api/assurance/approvals, the signed "
        "receipt's /api/assurance/receipt/sign",
        "the preflight report is cached CACHE_SECONDS; the others: none",
        "unchanged",
        "the gate asks once per window; an approval is one call per run of the command a person "
        "runs; a signature is a read that stores nothing",
        (
            "test_the_preflight_gate_asks_the_engine_once_per_window",
            "test_an_approval_run_once_makes_one_approval_call",
            "test_a_signed_receipt_read_twice_writes_nothing",
        ),
    ),
    "defender-gateway": Boundary(
        "DefenderMiddleware._call_engine: the engine's /defend judgment of one request",
        "none: one judgment per request arriving", "unchanged",
        "one /defend call per request (a lost answer is not re-asked); a stop is never sent",
        ("test_one_request_is_judged_by_one_defend_call_and_a_stop_by_none",),
    ),
    "retest-requirement": Boundary(
        "RetestRequirement opened by drift or a fired latent condition; a re-derive resolves it",
        "_has_open_requirement per claim identity + uq_open_retest_per_claim",
        "unchanged",
        "one open retest per claim however many checks run",
        ("test_an_invalidation_check_run_twice_opens_one_retest_per_claim",),
    ),
    "claim-derivation": Boundary(
        "derive_claims: AssuranceClaim versions and their ClaimEvents",
        "the claim identity fingerprint + its input fingerprint and policy; uq_current_claim",
        "unchanged",
        "a re-derive with nothing moved writes no version and no event",
        ("test_a_re_derive_with_nothing_moved_writes_no_version_and_no_event",),
    ),
    "claim-transition": Boundary(
        "apply_claim_transition: a person's move of a claim, and its ClaimEvent",
        "the lifecycle state machine (no status moves to itself)",
        "unchanged",
        "a move replayed is refused (400) and writes nothing; a take-down (a stop) replayed is "
        "processed again and recorded, the claim's status moved once",
        (
            "test_a_persons_move_replayed_writes_one_event",
            "test_a_take_down_replayed_with_a_key_is_processed_again_and_moves_the_claim_once",
        ),
    ),
    "evidence-audit": Boundary(
        "The evidence audit's writes: an invalidation of an item, the audit's ClaimEvent, an item "
        "recorded (record_claim_evidence -- no route, no caller yet)",
        "an attributed invalidation is refused again; the audit writes an event only on a move; "
        "recording: none",
        "unchanged",
        "an invalidation replayed is refused; an item recorded twice is two items and moves the "
        "claim once",
        (
            "test_an_evidence_invalidation_replayed_is_refused_and_moves_the_claim_once",
            "test_the_same_evidence_recorded_twice_moves_the_claim_once",
        ),
    ),
    "failsafe-drafts": Boundary(
        "FailsafeCommand drafts: a pause, stand-down or terminate (stops) and a resume or release; "
        "the engine acts only on one signed and served by its poll",
        "a stop draft: the identical unsigned draft is returned (its own rule, applied every time); "
        "a resume/release: none",
        "unchanged: a stop route, which the key layer never touches",
        "a stop draft replayed is processed each time; a start draft replayed is a second unsigned "
        "draft, which no poll serves",
        (
            "test_a_stop_draft_replayed_with_a_key_is_processed_each_time",
            "test_a_start_draft_replayed_is_two_unsigned_drafts_no_poll_serves",
        ),
    ),
    "engine-poll": Boundary(
        "GET /api/failsafe/pending/: a signed command served to the engine on every poll",
        "the command's nonce, which the engine's ledger applies once", "unchanged",
        "polled twice, the same command with the same nonce",
        ("test_a_signed_command_polled_twice_is_one_nonce",),
    ),
    "scan-ingest": Boundary(
        "ingest_scan: a completed scan's findings into Finding rows (which the severity dispatch "
        "pushes)",
        "Finding unique per (deployment, fingerprint), get_or_create", "unchanged",
        "a scan ingested twice records each finding once",
        ("test_a_scan_ingested_twice_records_each_finding_once",),
    ),
}

#: Every effect call site the code holds, as :func:`effect_sites` names it, and the
#: boundary it belongs to.
SITES = {
    "ai_engine/services/cyberengine_client.py::CyberEngineClient._send_post::requests.post": "engine-transport",
    "ai_engine/services/cyberengine_client.py::CyberEngineClient.defend_log_file::requests.post": "engine-transport",
    "assurance/connectors/base.py::RequestsTransport.post::requests.post": "engine-transport",
    "ai_engine/services/preflight.py::_attest_routes::attestation_check": "engine-governance",
    "ai_engine/services/preflight.py::check::assurance_check": "engine-governance",
    "pentest/management/commands/approve_deployment.py::Command.handle::assurance_approve": "engine-governance",
    "pentest/management/commands/approve_deployment.py::Command.handle::assurance_check": "engine-governance",
    "assurance/views.py::DeploymentViewSet.signed_assurance_receipt::sign_assurance_receipt": "engine-governance",
    "assurance/connectors/base.py::Connector.comment_on::transport.post": "connector-push-dispatch",
    "assurance/connectors/base.py::Connector.push_finding::transport.post": "connector-push-dispatch",
    "assurance/dispatch.py::_closed_issue::comment_on": "connector-push-dispatch",
    "assurance/dispatch.py::_dispatch_one::push_finding": "connector-push-dispatch",
    "assurance/dispatch.py::_record::DispatchAttempt.objects.get_or_create": "connector-push-dispatch",
    "assurance/connectors/webhook.py::WebhookConnector.push_receipt::transport.post": "webhook-receipt-push",
    "assurance/dispatch.py::_record_owed_if_missing::DecisionDispatchDue.objects.get_or_create": "decision-dispatch-owed",
    "assurance/dispatch.py::record_blocking_dispatch_owed::DecisionDispatchDue.objects.create": "decision-dispatch-owed",
    "assurance/dispatch.py::run_blocking_decision_dispatch::DecisionDispatchDue.objects.get_or_create": "decision-dispatch-owed",
    "assurance/invalidation.py::_open_requirement::RetestRequirement.objects.create": "retest-requirement",
    "assurance/views.py::DeploymentViewSet.connector_push::push_finding": "connector-push-manual",
    "audit/middleware.py::DefenderMiddleware._call_engine::requests.post": "defender-gateway",
    "detection/views.py::CVEClassifyAPIView.post::classify_cve": "engine-analysis",
    "detection/views.py::DefenderFileScanAPIView.post::defend_log_text": "engine-analysis",
    "detection/views.py::DefenderTextScanAPIView.post::defend_log_text": "engine-analysis",
    "failsafe/views.py::_insert_draft::FailsafeCommand.objects.create": "failsafe-drafts",
    "failsafe/views.py::_new_draft::FailsafeCommand.objects.create": "failsafe-drafts",
    "pentest/utils.py::send_pentest_scan_email::EmailMessage": "report-email",
    "pentest/views.py::resend_scan_email::send_pentest_scan_email": "report-email",
    "pentest/views.py::run_llm_pentest_scan::send_pentest_scan_email": "report-email",
    "pentest/views.py::run_pentest_scan::send_pentest_scan_email": "report-email",
    "pentest/views.py::run_llm_pentest_scan::PentestScan.objects.create": "engine-llm-scan-start",
    "pentest/views.py::run_llm_pentest_scan::run_llm_scan": "engine-llm-scan-start",
    "pentest/views.py::run_pentest_scan::PentestScan.objects.create": "engine-scan-start",
    "pentest/views.py::_send_launch::run_scan": "engine-scan-start",
    "pentest/views.py::_send_stop::abort_scan": "engine-scan-stop",
    "pentest/views_llm.py::PentestLLMScanView.post::PentestScan.objects.create": "llm-scan-view-unrouted",
    "pentest/views_llm.py::PentestLLMScanView.post::run_llm_scan": "llm-scan-view-unrouted",
}

# ---------------------------------------------------------------------------
# Reading the code for effect call sites
# ---------------------------------------------------------------------------

_NOT_FIRST_PARTY = frozenset({"tests", "node_modules", "site-packages", "__pycache__", "migrations"})
_CLIENT = "ai_engine/services/cyberengine_client.py"
#: ``requests`` and ``httpx`` calls that write.
_WRITE_VERBS = frozenset({"post", "put", "patch", "delete", "request"})
#: What sends e-mail, and what opens a connection some other way.
_MAIL = frozenset({"EmailMessage", "EmailMultiAlternatives", "send_mail", "send_mass_mail", "mail_admins", "mail_managers"})
_OTHER_TRANSPORTS = frozenset({"urlopen", "HTTPConnection", "HTTPSConnection", "SMTP", "SMTP_SSL"})
#: The connector calls that carry a finding or a receipt out.
_CONNECTOR_CALLS = frozenset({"push_finding", "comment_on", "push_receipt"})
#: Durable rows another process acts on: the dispatch runner and sweeper, the
#: re-derive that resolves a retest, the engine's poll, the scan's ingest.
_ACTED_ON = frozenset({"DispatchAttempt", "DecisionDispatchDue", "RetestRequirement", "FailsafeCommand", "PentestScan"})
_ROW_WRITES = frozenset({"create", "get_or_create", "update_or_create", "bulk_create"})


def _first_party_python():
    sources = {}
    for directory, subdirectories, files in os.walk(REPO):
        here = Path(directory)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in _NOT_FIRST_PARTY and not name.startswith(".") and not (here / name / "pyvenv.cfg").exists()
        )
        for name in sorted(files):
            if name.endswith(".py"):
                sources[(here / name).relative_to(REPO).as_posix()] = (here / name).read_text()
    return sources


def _engine_writes(client_tree) -> set[str]:
    """CyberEngineClient's public methods that POST to the engine."""
    (client,) = [n for n in client_tree.body if isinstance(n, ast.ClassDef) and n.name == "CyberEngineClient"]
    found = set()
    for method in client.body:
        if not isinstance(method, ast.FunctionDef) or method.name.startswith("_"):
            continue
        for node in ast.walk(method):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and (
                (node.value.id == "self" and node.attr in {"_post", "_send_post"})
                or (node.value.id == "requests" and node.attr == "post")
            ):
                found.add(method.name)
    return found


class _Sites(ast.NodeVisitor):
    def __init__(self, path, engine_writes, mailers, found):
        self.path, self.engine_writes, self.mailers, self.found = path, engine_writes, mailers, found
        self.scope = []

    def _enter(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _enter

    def _site(self, what):
        self.found.add(f"{self.path}::{'.'.join(self.scope) or '<module>'}::{what}")

    def visit_Attribute(self, node):
        # A reference, called or not: `within_deadline(requests.post, ...)` sends too.
        if isinstance(node.value, ast.Name) and node.value.id in {"requests", "httpx"} and node.attr in _WRITE_VERBS:
            self._site(f"{node.value.id}.{node.attr}")
        self.generic_visit(node)

    def visit_Call(self, node):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name in _MAIL or name in _OTHER_TRANSPORTS or name == "send_messages":
            self._site(name)
        if name in self.mailers:
            self._site(name)
        if isinstance(func, ast.Attribute):
            if name in self.engine_writes and self.path != _CLIENT:
                self._site(name)
            if name in _CONNECTOR_CALLS:
                self._site(name)
            if name == "post" and isinstance(func.value, ast.Name) and func.value.id == "transport":
                self._site("transport.post")
            owner = func.value
            if (
                name in _ROW_WRITES
                and isinstance(owner, ast.Attribute)
                and owner.attr == "objects"
                and isinstance(owner.value, ast.Name)
                and owner.value.id in _ACTED_ON
            ):
                self._site(f"{owner.value.id}.objects.{name}")
        self.generic_visit(node)


def _mailers(trees) -> set[str]:
    """The functions that build or send an e-mail themselves: a call of one is an e-mail sent."""
    found = set()
    for tree in trees.values():
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                isinstance(n, ast.Call) and (getattr(n.func, "attr", None) or getattr(n.func, "id", None)) in _MAIL
                for n in ast.walk(fn)
            ):
                found.add(fn.name)
    return found


def effect_sites(sources=None) -> set[str]:
    """Every call site in first-party code (tests and migrations aside) that makes an
    external effect, as ``path::scope::what``."""
    sources = _first_party_python() if sources is None else sources
    trees = {path: ast.parse(text) for path, text in sources.items()}
    engine_writes = _engine_writes(trees[_CLIENT])
    mailers = _mailers(trees)
    found = set()
    for path, tree in sorted(trees.items()):
        _Sites(path, engine_writes, mailers, found).visit(tree)
    return found


# ---------------------------------------------------------------------------
# Fakes: the engine, a tracker, a webhook -- counted, never the network
# ---------------------------------------------------------------------------

RECORDED = REPO / "tests" / "fixtures" / "engine_launch" / "pr71-f4610ae" / "scan-finished-inline.json"


def _recorded_scan_answer() -> dict:
    """athena-engine #71's 200 to a scan launch that finished inside the backend's wait,
    as the real engine sent it (tests/fixtures/engine_launch)."""
    exchanges = json.loads(RECORDED.read_text())["exchanges"]
    (launch,) = [e for e in exchanges if e["request"]["method"] == "POST" and e["request"]["path"] == "/api/scan"]
    return launch["body"]


def _http(status, body=None, headers=None):
    response = requests.Response()
    response.status_code = status
    response._content = b"" if body is None else json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    for name, value in (headers or {}).items():
        response.headers[name] = value
    return response


class FakeEngine:
    """Every HTTP call this process makes, answered in process and counted.

    It stands in for ``requests.post`` and ``requests.get`` themselves, so nothing a
    test does can reach the network: the engine's routes are answered as the engine
    answers them, the gateway's ``/defend`` is refused (as the suite's unreachable
    127.0.0.1:8001 is), and anything else is a refused connection."""

    def __init__(self, base):
        self.base = base.rstrip("/")
        self.calls = []
        self.lost = set()
        self.during = {}
        self.defend = None
        self.scan_answer = _recorded_scan_answer()
        #: As athena-engine #77 keeps them: each Idempotency-Key's recorded answer to a
        #: scan launch, given again, marked replayed, to the same key.
        self.keys = {}
        #: The runs this engine started, by id (the scans of the customer), and the
        #: headers of every request, by method and path.
        self.runs = {}
        self.headers = []

    def count(self, method, path):
        return sum(1 for m, p, _ in self.calls if (m, p) == (method, path))

    def post(self, url, json=None, headers=None, timeout=None, **_kwargs):  # noqa: A002 - requests' own name
        return self._answer("POST", url, json, headers)

    def get(self, url, headers=None, timeout=None, params=None, **_kwargs):
        return self._answer("GET", url, None, headers)

    def _answer(self, method, url, body, headers=None):
        if not url.startswith(self.base):
            raise requests.ConnectionError(f"nothing is reachable from this test: {url}")
        path = url[len(self.base):].split("?")[0]
        self.calls.append((method, path, body))
        self.headers.append((method, path, dict(headers or {})))
        if path in self.during:
            self.during.pop(path)()
        if path == "/defend":
            if self.defend is None:
                raise requests.ConnectionError("the gateway's engine is not part of this test")
            return self.defend()
        if (method, path) in self.lost:
            # The request arrived and was acted on; its answer never came back.
            self._route(method, path, headers)
            raise rex.ReadTimeout("the engine's answer never came back")
        return self._route(method, path, headers)

    def _route(self, method, path, headers=None):
        if (method, path) == ("POST", "/api/scan"):
            key = (headers or {}).get("Idempotency-Key")
            if key in self.keys:
                return _http(200, copy.deepcopy(self.keys[key]), {"Idempotent-Replayed": "true"})
            answer = copy.deepcopy(self.scan_answer)
            answer["run_id"] = str(uuid.uuid4())
            self.runs[answer["run_id"]] = copy.deepcopy(answer)
            if key is not None:
                self.keys[key] = copy.deepcopy(answer)
            return _http(200, answer)
        if method == "GET" and path.removeprefix("/api/scans/") in self.runs:
            return _http(200, self.runs[path.removeprefix("/api/scans/")])
        if method == "POST" and path.startswith("/api/scans/") and path.endswith("/abort"):
            run = self.runs.get(path.removeprefix("/api/scans/").removesuffix("/abort"))
            if run is None:
                return _http(404, {"detail": "No such scan run"})
            if run["state"] in ("completed", "failed", "aborted"):
                return _http(200, {"run_id": run["run_id"], "state": run["state"], "detail": "not running"})
            run["state"] = "aborting"
            return _http(200, {"run_id": run["run_id"], "state": "aborting", "reason": "x", "recorded": True})
        if (method, path) == ("POST", "/api/llm-scan"):
            return _http(200, {"results": [{"type": "system_prompt_extraction", "severity": "high",
                                            "message": "the system prompt was disclosed"}]})
        if (method, path) == ("POST", "/api/defend-log/text"):
            return _http(200, {"alerts": [], "summary": "nothing found"})
        if (method, path) == ("POST", "/api/classify-cve"):
            return _http(200, {"label": "rce", "confidence_note": "engine's own label"})
        if (method, path) == ("POST", "/api/assurance/check"):
            return _http(200, {"verdict": "unchanged", "detail": "as approved"})
        if (method, path) == ("GET", "/api/extensions"):
            return _http(200, {"verdict": "unchanged", "extensions": []})
        if method == "GET" and path.startswith("/api/authority/unattributed"):
            return _http(200, {"effects": [], "count": 0})
        if (method, path) == ("POST", "/api/attestation/check"):
            return _http(200, {"verdict": "unchanged"})
        if (method, path) == ("GET", "/api/assurance/measured"):
            return _http(200, {"measured": {"egress": ["engine.test"]}})
        if (method, path) == ("POST", "/api/assurance/approvals"):
            return _http(200, {"id": "approval-1", "tuple_digest": "sha256:ab12"})
        if (method, path) == ("POST", "/api/assurance/receipt/sign"):
            return _http(503, {"detail": "no signing key on this engine"})
        return _http(404, {"detail": f"the engine has no {method} {path}"})


@pytest.fixture(autouse=True)
def engine(monkeypatch):
    """The engine -- and every other HTTP endpoint -- for every test in this module."""
    fake = FakeEngine(django_settings.CYBERENGINE_URL)
    monkeypatch.setattr(requests, "post", fake.post)
    monkeypatch.setattr(requests, "get", fake.get)
    return fake


@pytest.fixture(autouse=True)
def _outbox(settings):
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    mail.outbox = []
    preflight.clear_cache()
    yield
    preflight.clear_cache()


@pytest.fixture()
def credential_key(settings):
    from cryptography.fernet import Fernet

    settings.ASSURANCE_CREDENTIAL_KEY = Fernet.generate_key().decode()


class _Answer:
    """A tracker's answer: what the adapters read (status, JSON, text)."""

    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeJira:
    """A Jira that files what it is sent and finds it again: every create is an issue,
    and a search answers every issue in the project (the look verifies each one's
    marker). ``lose_first_answer``: the first create lands and its answer is lost."""

    deadline = 30.0

    def __init__(self, lose_first_answer=False):
        self.issues = []
        self.creates = 0
        self.lose_first_answer = lose_first_answer

    def post(self, url, *, headers, json):  # noqa: A002 - the transport's own name
        if url.endswith("/rest/api/2/issue"):
            self.creates += 1
            key = f"SEC-{len(self.issues) + 1}"
            self.issues.append({"key": key, "description": json["fields"]["description"],
                                "created": timezone.now().strftime("%Y-%m-%dT%H:%M:%S.000+0000")})
            if self.lose_first_answer and self.creates == 1:
                raise rex.ReadTimeout("the tracker's answer never came back")
            return _Answer(201, {"key": key})
        raise AssertionError(f"this tracker takes no POST to {url}")

    def get(self, url, *, headers, params=None):
        issues = [
            {"key": i["key"], "fields": {"status": {"statusCategory": {"key": "new"}},
                                         "created": i["created"], "description": i["description"]}}
            for i in self.issues
        ]
        if url.endswith("/rest/api/3/search/jql"):
            return _Answer(200, {"issues": issues, "isLast": True})
        for issue in issues:
            if url.endswith(f"/rest/api/2/issue/{issue['key']}"):
                return _Answer(200, issue)
        return _Answer(404, {"errorMessages": ["no such issue"]})


class FakeWebhook:
    """A webhook receiver that records what arrives; ``lose_first_answer`` loses the first answer."""

    def __init__(self, lose_first_answer=False):
        self.received = []
        self.lose_first_answer = lose_first_answer

    def post(self, url, *, headers, json):  # noqa: A002 - the transport's own name
        self.received.append(dict(headers))
        if self.lose_first_answer and len(self.received) == 1:
            raise rex.ReadTimeout("the receiver's answer never came back")
        return _Answer(202, {"accepted": True})


# ---------------------------------------------------------------------------
# Setting the scene
# ---------------------------------------------------------------------------

TARGET = "https://offline.invalid/"
SCAN_URL = "/api/pentest/scan/"
LLM_SCAN_URL = "/api/pentest/llm-scan/"


def _user(role=User.Roles.ANALYST):
    return User.objects.create_user(username=f"u-{uuid.uuid4().hex[:10]}", password=None, role=role)


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _engagement(user, **over):
    now = timezone.now()
    values = {
        "created_by": user,
        "name": "Client Q3",
        "status": "running",
        "scope_hosts": ["offline.invalid"],
        "testing_window_start": now - timedelta(hours=1),
        "testing_window_end": now + timedelta(hours=1),
    }
    values.update(over)
    return Engagement.objects.create(**values)


@pytest.fixture()
def scan_path(monkeypatch):
    """The scan route's own collaborators that are not under test here: name resolution
    of the target, the preflight gate (its own boundary, tested below) and the PDF."""
    monkeypatch.setattr("pentest.views.target_is_out_of_bounds", lambda url: None)
    monkeypatch.setattr("pentest.views.preflight.check", lambda client, tenant_id=None: {"verdict": "unchanged"})
    monkeypatch.setattr("pentest.views.render_scan_pdf_bytes", lambda scan: b"%PDF-1.4 report")
    monkeypatch.setattr("pentest.views.save_pdf_to_scan", lambda scan, pdf: None)


def _scan_body(engagement, **over):
    return {"url": TARGET, "consent": True, "engagement_id": engagement.pk,
            "recipient_email": "client@example.com", **over}


def _deployment(owner=None):
    owner = owner or _user(User.Roles.ADMIN)
    return Deployment.objects.create(name=f"dep-{uuid.uuid4().hex[:8]}", owner=owner)


def _finding(dep, severity="critical"):
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{uuid.uuid4().hex[:12]}", finding_type="xss",
        title="Reflected input on /search", severity=severity,
    )


def _jira(dep):
    binding = ConnectorBinding(
        deployment=dep, connector="jira", enabled=True,
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    binding.set_secret("jira-token")
    binding.save()
    return binding


def _webhook(dep):
    binding = ConnectorBinding(deployment=dep, connector="webhook", enabled=True,
                               endpoint={"url": "https://hooks.example/athena"})
    binding.set_secret("webhook-token")
    binding.save()
    return binding


def _claimed_deployment():
    """A deployment whose EFFECTIVE_ACCESS claim the deriver reads VERIFIED."""
    dep = _deployment()
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
        classification=Asset.Classification.APPROVED, metadata={"tools": ["reporter"]},
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="reporter", identifier="reporter",
        classification=Asset.Classification.APPROVED, metadata={"permissions": ["query"]},
    )
    derive_claims(dep)
    return dep, _access_claim(dep)


def _access_claim(dep):
    return AssuranceClaim.objects.filter(deployment=dep, claim_type=ClaimType.EFFECTIVE_ACCESS).current().get()


def _evidence(claim, **over):
    """An evidence item that carries weight against ``claim`` (independent, live, naming it)."""
    now = timezone.now()
    kw = dict(
        outcome=ClaimVerdict.PASS.value,
        origin=ClaimEvidence.Origin.INDEPENDENT.value,
        evidence_class=EvidenceClass.TECHNICALLY_VERIFIED.value,
        subject_deployment=str(claim.deployment.uuid),
        subject_claim_type=claim.claim_type,
        subject_route=serving_route_now(claim.deployment),
        subject_inputs=claim.input_fingerprint,
        observed_at=now - timedelta(minutes=2),
        state_check_ref="achilles:reach-probe/run-4411",
        state_checked_at=now - timedelta(minutes=1),
        signer="athena-scan-key-1",
        signature_verified=True,
        content_digest="sha256:7f3a9c",
        actor_account="athena-scanner",
        actor_account_kind=ClaimEvidence.AccountKind.SERVICE_ACCOUNT.value,
    )
    kw.update(over)
    return kw


# ===========================================================================
# engine-scan-start
# ===========================================================================


def test_a_scan_launch_replayed_with_its_key_starts_one_engine_scan(engine, scan_path):
    """The retried tool call: the client never saw the answer and sends the launch
    again with the same key. One scan of the customer's system, one row, one e-mail,
    and the replay is answered exactly what the first was."""
    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))

    first = client.post(SCAN_URL, body, format="json", **{KEY: "launch-1"})
    replay = client.post(SCAN_URL, body, format="json", **{KEY: "launch-1"})

    assert first.status_code == 200, first.content
    assert engine.count("POST", "/api/scan") == 1, "the replay scanned the customer's system a second time"
    assert PentestScan.objects.count() == 1
    assert len(mail.outbox) == 1, "the replay e-mailed the report again"
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert replay["Idempotent-Replayed"] == "true"


def test_a_scan_launch_whose_engine_answer_was_lost_is_not_launched_again_by_its_replay(engine, scan_path):
    """A retry after a lost acknowledgement: the engine took the launch and its answer
    never came back. The route records what it knows -- whether the engine started a
    run is unknown (#363: it was recorded FAILED, which licenses a second launch) --
    and the replay answers that record: it never launches a second scan. The engine
    was sent the scan's own key, which is how a reconcile asks it what became of it."""
    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))
    engine.lost.add(("POST", "/api/scan"))

    first = client.post(SCAN_URL, body, format="json", **{KEY: "lost-1"})
    replay = client.post(SCAN_URL, body, format="json", **{KEY: "lost-1"})

    assert first.status_code == 202, first.content
    assert first.json()["status"] == PentestScan.STATUS_UNKNOWN
    assert engine.count("POST", "/api/scan") == 1, "a retry after a lost answer launched a second scan"
    assert replay.status_code == 202
    assert replay.json() == first.json()
    (scan,) = PentestScan.objects.all()
    assert scan.status == PentestScan.STATUS_UNKNOWN
    assert [h.get("Idempotency-Key") for m, p, h in engine.headers if (m, p) == ("POST", "/api/scan")] == [
        scan.launch_key
    ]


def test_a_lost_launch_reconciled_again_and_again_scans_the_customer_once(engine, scan_path):
    """The engine took the launch and its answer was lost; the first reconcile's answer
    is lost too; the second is read. Three sends of the same launch, each with the
    scan's own key: one scan of the customer (one run), which is adopted, and the scan
    completes with that run's findings. Asked once more, nothing is sent."""
    analyst = _user()
    client = _client(analyst)
    engine.lost.add(("POST", "/api/scan"))
    first = client.post(SCAN_URL, _scan_body(_engagement(analyst)), format="json")
    scan = PentestScan.objects.get(uuid=first.json()["scan_id"])
    reconcile = f"/api/pentest/scans/{scan.uuid}/reconcile/"

    again = client.post(reconcile, format="json")
    engine.lost.clear()
    read = client.post(reconcile, format="json")
    after = client.post(reconcile, format="json")

    assert (first.status_code, again.status_code, read.status_code, after.status_code) == (202, 202, 200, 409)
    assert engine.count("POST", "/api/scan") == 3
    assert len(engine.runs) == 1, "a reconcile scanned the customer a second time"
    (run_id,) = engine.runs
    assert {h.get("Idempotency-Key") for m, p, h in engine.headers if (m, p) == ("POST", "/api/scan")} == {
        scan.launch_key
    }
    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_COMPLETED
    assert scan.engine_run_id == run_id
    assert read.json()["result"] == engine.runs[run_id]["result"]
    assert mail.outbox == [], "a reconcile mailed the report the launch's request asked for"


def test_a_scan_replayed_after_its_engagement_was_withdrawn_starts_nothing(engine, scan_path):
    """A replay never executes under an authority withdrawn since the first attempt: it
    answers what the first was answered, and starts nothing. A NEW request -- a new key
    -- is judged afresh, and refused."""
    analyst = _user()
    client = _client(analyst)
    engagement = _engagement(analyst)
    body = _scan_body(engagement)

    first = client.post(SCAN_URL, body, format="json", **{KEY: "before-withdrawal"})
    withdrawn = client.patch(f"/api/pentest/engagements/{engagement.pk}/", {"status": "paused"}, format="json")
    replay = client.post(SCAN_URL, body, format="json", **{KEY: "before-withdrawal"})
    fresh = client.post(SCAN_URL, body, format="json", **{KEY: "after-withdrawal"})

    assert first.status_code == 200
    assert withdrawn.status_code == 200
    assert replay.status_code == 200 and replay["Idempotent-Replayed"] == "true"
    assert replay.json() == first.json()
    assert fresh.status_code == 403
    assert engine.count("POST", "/api/scan") == 1


def test_a_scan_replayed_by_an_account_demoted_since_is_refused_before_any_record(engine, scan_path):
    """The account is checked on every request, a replay included: authentication and
    the route's permission run before the key is read."""
    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))

    first = client.post(SCAN_URL, body, format="json", **{KEY: "demoted"})
    User.objects.filter(pk=analyst.pk).update(role=User.Roles.VIEWER)
    analyst.refresh_from_db()
    client.force_authenticate(user=analyst)
    replay = client.post(SCAN_URL, body, format="json", **{KEY: "demoted"})

    assert first.status_code == 200
    assert replay.status_code == 403
    assert "scan_id" not in replay.json()
    assert engine.count("POST", "/api/scan") == 1


def test_the_same_key_with_another_request_is_refused_and_starts_nothing(engine, scan_path):
    analyst = _user()
    client = _client(analyst)
    engagement = _engagement(analyst)

    first = client.post(SCAN_URL, _scan_body(engagement), format="json", **{KEY: "reused"})
    other = client.post(SCAN_URL, _scan_body(engagement, url="https://offline.invalid/admin"),
                        format="json", **{KEY: "reused"})

    assert first.status_code == 200
    assert other.status_code == 422, other.content
    assert "different request" in other.json()["detail"]
    assert engine.count("POST", "/api/scan") == 1
    assert PentestScan.objects.count() == 1


def test_a_replay_while_the_first_is_still_running_is_refused_and_starts_nothing(engine, scan_path):
    """The replay arrives while the first launch is still waiting on the engine: it is
    told the outcome is not known yet (409) and starts nothing."""
    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))
    during = {}
    engine.during["/api/scan"] = lambda: during.setdefault(
        "replay", _client(analyst).post(SCAN_URL, body, format="json", **{KEY: "in-flight"})
    )

    first = client.post(SCAN_URL, body, format="json", **{KEY: "in-flight"})

    assert first.status_code == 200
    assert during["replay"].status_code == 409, during["replay"].content
    assert "unknown" in during["replay"].json()["detail"]
    assert engine.count("POST", "/api/scan") == 1


def test_a_launch_that_raised_before_it_recorded_an_answer_reads_as_unknown(engine, scan_path, monkeypatch):
    """The engine ran the scan, then the route raised before it answered: this backend
    never observed how the request ended. The key records it as unknown -- never as
    done or failed -- and its replay starts nothing."""
    from idempotency.models import IdempotencyRecord

    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))

    def renderer_crashes(scan):
        raise RuntimeError("the renderer crashed")

    monkeypatch.setattr("pentest.views.render_scan_pdf_bytes", renderer_crashes)
    with pytest.raises(RuntimeError):
        client.post(SCAN_URL, body, format="json", **{KEY: "crashed"})
    replay = client.post(SCAN_URL, body, format="json", **{KEY: "crashed"})

    assert IdempotencyRecord.objects.get(key="crashed").state == IdempotencyRecord.State.UNKNOWN
    assert replay.status_code == 409
    assert "unknown" in replay.json()["detail"]
    assert engine.count("POST", "/api/scan") == 1


def test_a_scan_launch_without_a_key_is_unchanged_and_its_retry_scans_again(engine, scan_path):
    """No key, no change: a retry is a new launch. The README says so."""
    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))

    assert client.post(SCAN_URL, body, format="json").status_code == 200
    assert client.post(SCAN_URL, body, format="json").status_code == 200

    assert engine.count("POST", "/api/scan") == 2
    assert PentestScan.objects.count() == 2


# ---------------------------------------------------------------------------
# The key's own bounds
# ---------------------------------------------------------------------------


def test_a_key_is_forgotten_after_its_ttl_and_then_runs_as_a_new_request(engine, scan_path):
    from idempotency.models import IdempotencyRecord

    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))

    client.post(SCAN_URL, body, format="json", **{KEY: "old"})
    IdempotencyRecord.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    again = client.post(SCAN_URL, body, format="json", **{KEY: "old"})

    assert again.status_code == 200
    assert "Idempotent-Replayed" not in again
    assert engine.count("POST", "/api/scan") == 2
    assert IdempotencyRecord.objects.filter(key="old").count() == 1


def test_an_account_keeps_at_most_its_bound_of_keys(settings):
    from idempotency.models import IdempotencyRecord

    settings.IDEMPOTENCY_KEYS_PER_ACCOUNT = 2
    analyst = _user()
    scan = PentestScan.objects.create(user=analyst, target_url=TARGET, consent=True,
                                      status=PentestScan.STATUS_COMPLETED, recipient_email="client@example.com")
    client = _client(analyst)
    url = f"/api/pentest/scans/{scan.uuid}/email/"

    with mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"):
        for key in ("a", "b", "c"):
            assert client.post(url, {}, format="json", **{KEY: key}).status_code == 200
        assert set(IdempotencyRecord.objects.filter(user=analyst).values_list("key", flat=True)) == {"b", "c"}
        # "a" was forgotten: the bound's price, said in the README -- it runs again.
        client.post(url, {}, format="json", **{KEY: "a"})

    assert len(mail.outbox) == 4


def test_an_answer_past_the_size_bound_is_replayed_as_its_status_and_scalars(engine, scan_path, settings):
    settings.IDEMPOTENCY_MAX_RESPONSE_BYTES = 256
    analyst = _user()
    client = _client(analyst)
    body = _scan_body(_engagement(analyst))

    first = client.post(SCAN_URL, body, format="json", **{KEY: "large"})
    replay = client.post(SCAN_URL, body, format="json", **{KEY: "large"})

    assert first.status_code == replay.status_code == 200
    assert replay.json()["scan_id"] == first.json()["scan_id"]
    assert "result" not in replay.json()
    assert "not replayed whole" in replay.json()["idempotency"]["note"]
    assert engine.count("POST", "/api/scan") == 1


@pytest.mark.parametrize("bad", ["", "   ", "x" * 256, "tab\there", "café"])
def test_a_key_that_is_not_one_is_refused_and_starts_nothing(engine, scan_path, bad):
    analyst = _user()
    response = _client(analyst).post(SCAN_URL, _scan_body(_engagement(analyst)), format="json", **{KEY: bad})

    assert response.status_code == 400
    assert "Idempotency-Key" in response.json()["detail"]
    assert engine.count("POST", "/api/scan") == 0


# ===========================================================================
# engine-llm-scan-start, llm-scan-view-unrouted
# ===========================================================================


def test_an_llm_scan_launch_replayed_with_its_key_starts_one_engine_run(engine, scan_path):
    analyst = _user()
    client = _client(analyst)
    body = {
        "target_name": "Client LLM", "adapter": "openai_style",
        "base_url": "https://offline.invalid/v1/chat/completions", "model": "m",
        "attacks": ["direct_prompt_injection"], "max_turns": 2, "consent": True,
        "engagement_id": _engagement(analyst).pk, "recipient_email": "client@example.com",
    }

    first = client.post(LLM_SCAN_URL, body, format="json", **{KEY: "llm-1"})
    replay = client.post(LLM_SCAN_URL, body, format="json", **{KEY: "llm-1"})

    assert first.status_code == 200, first.content
    assert engine.count("POST", "/api/llm-scan") == 1, "the replay ran the red team against the model again"
    assert PentestScan.objects.count() == 1
    assert len(mail.outbox) == 1
    assert replay.json() == first.json()


def test_the_unrouted_llm_scan_view_is_reachable_by_no_url():
    from pentest.views_llm import PentestLLMScanView

    def callbacks(resolver):
        for pattern in resolver.url_patterns:
            if hasattr(pattern, "url_patterns"):
                yield from callbacks(pattern)
            else:
                yield pattern.callback

    reached = [cb for cb in callbacks(get_resolver()) if getattr(cb, "view_class", None) is PentestLLMScanView]
    assert reached == []


# ===========================================================================
# report-email
# ===========================================================================


def test_a_report_resend_replayed_with_its_key_sends_one_email():
    analyst = _user()
    scan = PentestScan.objects.create(user=analyst, target_url=TARGET, consent=True,
                                      status=PentestScan.STATUS_COMPLETED, recipient_email="client@example.com")
    client = _client(analyst)
    url = f"/api/pentest/scans/{scan.uuid}/email/"

    with mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"):
        first = client.post(url, {}, format="json", **{KEY: "resend-1"})
        replay = client.post(url, {}, format="json", **{KEY: "resend-1"})

    assert first.status_code == 200
    assert len(mail.outbox) == 1, "the replayed resend mailed the report twice"
    assert replay.json() == first.json()


# ===========================================================================
# connector-push-manual
# ===========================================================================


def test_a_manual_connector_push_replayed_with_its_key_files_one_ticket(credential_key, monkeypatch):
    admin = _user(User.Roles.ADMIN)
    dep = _deployment(admin)
    finding = _finding(dep)
    _jira(dep)
    tracker = FakeJira()
    monkeypatch.setattr("assurance.connectors.RequestsTransport", lambda *a, **k: tracker)
    client = _client(admin)
    url = f"/api/assurance/deployments/{dep.uuid}/connectors/jira/push/"

    first = client.post(url, {"finding": str(finding.uuid)}, format="json", **{KEY: "push-1"})
    replay = client.post(url, {"finding": str(finding.uuid)}, format="json", **{KEY: "push-1"})

    assert first.status_code == 200 and first.json()["ok"] is True, first.content
    assert tracker.creates == 1, "the replayed push filed a second ticket in the customer's tracker"
    assert replay.json() == first.json()
    assert replay["Idempotent-Replayed"] == "true"


# ===========================================================================
# connector-push-dispatch, webhook-receipt-push
# ===========================================================================


def test_a_finding_dispatched_twice_files_one_ticket(credential_key):
    dep = _deployment()
    finding = _finding(dep)
    _jira(dep)
    tracker = FakeJira()

    dispatch.dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: tracker)
    dispatch.dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: tracker)

    assert tracker.creates == 1
    (attempt,) = DispatchAttempt.objects.filter(finding=finding)
    assert attempt.outcome == DispatchAttempt.Outcome.SENT


def test_a_dispatch_whose_answer_was_lost_is_found_not_filed_again(credential_key):
    """The ticket was created and the answer lost: the attempt is UNKNOWN, never FAILED,
    and the next trigger finds the issue by its marker instead of filing another."""
    dep = _deployment()
    finding = _finding(dep)
    _jira(dep)
    tracker = FakeJira(lose_first_answer=True)

    (lost,) = dispatch.dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY,
                                        transport_factory=lambda: tracker)
    assert lost.outcome == DispatchAttempt.Outcome.UNKNOWN
    (found,) = dispatch.dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY,
                                         transport_factory=lambda: tracker)

    assert tracker.creates == 1, "a retry after a lost answer filed a second ticket"
    assert found.outcome == DispatchAttempt.Outcome.SENT
    assert found.external_ref == "SEC-1"


def test_a_webhook_redelivery_carries_the_same_operation_id(credential_key):
    """A receiver that honours Idempotency-Key is sent the operation's durable id on
    every delivery, so a redelivery after a lost answer is one delivery there."""
    dep = _deployment()
    finding = _finding(dep)
    _webhook(dep)
    receiver = FakeWebhook(lose_first_answer=True)

    for _ in range(2):
        dispatch.dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY,
                                  transport_factory=lambda: receiver)

    assert len(receiver.received) == 2
    keys = {headers["Idempotency-Key"] for headers in receiver.received}
    assert keys == {dispatch.operation_id(finding, "webhook")}


def test_the_webhook_receipt_push_has_no_caller():
    assert not any(site.endswith("::push_receipt") for site in effect_sites())


# ===========================================================================
# decision-dispatch-owed
# ===========================================================================


def test_a_pause_replayed_owes_one_dispatch_and_files_one_ticket(credential_key):
    """A pause is a stop: each one is processed. What it owes is one row, however many
    pauses asked for it, and one ticket, however many runners run it -- the stop's own
    thread, a sweeper, the retry command."""
    admin = _user(User.Roles.ADMIN)
    dep = _deployment(admin)
    DispatchPolicy.objects.create(deployment=dep, enabled=True, min_severity="high", on_blocking_decision=True)
    _jira(dep)
    _finding(dep)
    tracker = FakeJira()
    client = _client(admin)

    for _ in range(2):
        paused = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True},
                             format="json", **{KEY: "pause-1"})
        assert paused.status_code == 200 and paused.json()["decision"] == Deployment.Decision.PAUSED

    (owed,) = DecisionDispatchDue.objects.filter(deployment=dep)
    assert owed.requests == 2, "the second pause was not processed"
    dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=lambda: tracker)
    dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=lambda: tracker)
    dispatch.retry_owed_blocking_dispatches(transport_factory=lambda: tracker)

    assert tracker.creates == 1


# ===========================================================================
# engine-scan-stop
# ===========================================================================


def test_a_scan_stop_sent_twice_is_sent_to_its_run_each_time(engine):
    """A stop is never deduplicated: each Stop sends the abort for the scan's run again
    -- key or no key -- for that run only, never abort-all, and never with an
    Idempotency-Key of its own."""
    analyst = _user()
    client = _client(analyst)
    live = copy.deepcopy(engine.scan_answer)
    live.update(run_id="run-live", state="running", done=False)
    engine.runs["run-live"] = live
    scan = PentestScan.objects.create(
        user=analyst, target_url=TARGET, consent=True, status=PentestScan.STATUS_PENDING, engine_run_id="run-live"
    )

    first = client.post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json", **{KEY: "stop-1"})
    second = client.post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json", **{KEY: "stop-1"})

    assert (first.status_code, second.status_code) == (200, 200), (first.content, second.content)
    aborts = [(p, h) for m, p, h in engine.headers if m == "POST" and "/abort" in p]
    assert [p for p, _ in aborts] == ["/api/scans/run-live/abort"] * 2
    assert not any("Idempotency-Key" in h for _, h in aborts)
    assert second.json()["stop"]["state"] == "delivered"


# ===========================================================================
# engine-transport
# ===========================================================================


def test_the_transports_send_a_request_once_even_when_its_answer_is_lost(engine):
    """Nothing re-sends on its own: a lost answer is raised to the caller, whose own
    record decides what happens next."""
    engine.lost.update({("POST", "/api/classify-cve"), ("POST", "/api/defend-log/file"), ("POST", "/api/scan")})
    client = CyberEngineClient.from_settings()

    with pytest.raises(EngineError):
        client.classify_cve("CVE-2024-0001")
    with pytest.raises(EngineError):
        client.defend_log_file(b"auth log", "auth.log")
    with pytest.raises(rex.ReadTimeout):
        RequestsTransport(deadline=5).post(f"{django_settings.CYBERENGINE_URL}/api/scan", headers={}, json={})

    assert engine.count("POST", "/api/classify-cve") == 1
    assert engine.count("POST", "/api/defend-log/file") == 1
    assert engine.count("POST", "/api/scan") == 1


# ===========================================================================
# engine-analysis
# ===========================================================================


def test_an_analysis_asks_the_engine_once_per_request(engine):
    """Analysis is a question, not an effect: each request asks once, and a replay asks
    again -- a second answer, kept, and nothing changed anywhere else."""
    client = _client(_user())

    for _ in range(2):
        assert client.post("/api/detection/defender/text/", {"content": "sshd: Failed password"},
                           format="json").status_code == 201
    assert client.post("/api/detection/cve/classify/", {"text": "CVE-2024-0001"}, format="json").status_code == 201

    assert engine.count("POST", "/api/defend-log/text") == 2
    assert engine.count("POST", "/api/classify-cve") == 1
    writes = [(m, p) for m, p, _ in engine.calls if m == "POST" and p != "/defend"]
    assert sorted(set(writes)) == [("POST", "/api/classify-cve"), ("POST", "/api/defend-log/text")]


# ===========================================================================
# engine-governance
# ===========================================================================


def test_the_preflight_gate_asks_the_engine_once_per_window(engine):
    client = CyberEngineClient.from_settings()

    preflight.check(client)
    preflight.check(client)

    assert engine.count("POST", "/api/assurance/check") == 1


def test_an_approval_run_once_makes_one_approval_call(engine):
    """A person runs the command; each run is one approval request, and nothing
    retries it on its own."""
    call_command("approve_deployment", "--approved-by", "ops@example.com", stdout=io.StringIO())

    assert engine.count("POST", "/api/assurance/approvals") == 1


def test_a_signed_receipt_read_twice_writes_nothing(engine):
    admin = _user(User.Roles.ADMIN)
    dep = _deployment(admin)
    client = _client(admin)
    url = f"/api/assurance/deployments/{dep.uuid}/signed-assurance-receipt/"

    with CaptureQueriesContext(connection) as queries:
        for _ in range(2):
            assert client.get(url).status_code == 200

    assert engine.count("POST", "/api/assurance/receipt/sign") == 2
    written = [q["sql"] for q in queries.captured_queries
               if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))]
    assert written == []


# ===========================================================================
# defender-gateway
# ===========================================================================


def test_one_request_is_judged_by_one_defend_call_and_a_stop_by_none(engine):
    def allow():
        response = requests.Response()
        response.status_code = 200
        response.raw = urllib3.HTTPResponse(body=io.BytesIO(b'{"action": "allow"}'), status=200,
                                            preload_content=False)
        return response

    gateway = DefenderMiddleware(lambda request: HttpResponse("ok"))
    factory = RequestFactory()

    engine.defend = allow
    gateway(factory.get("/api/pentest/scans/"))
    assert engine.count("POST", "/defend") == 1

    def lost():
        raise rex.ReadTimeout("the engine's decision never came back")

    engine.defend = lost
    gateway(factory.get("/api/pentest/scans/"))
    assert engine.count("POST", "/defend") == 2, "a lost decision was asked for again"

    dep = _deployment()
    gateway(factory.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True},
                         content_type="application/json"))
    assert engine.count("POST", "/defend") == 2, "a stop was sent to the engine"


# ===========================================================================
# retest-requirement, claim-derivation, claim-transition, evidence-audit
# ===========================================================================


def test_an_invalidation_check_run_twice_opens_one_retest_per_claim():
    dep, _claim = _claimed_deployment()
    Asset.objects.create(deployment=dep, kind=Asset.Kind.AGENT, name="late", identifier="late",
                         classification=Asset.Classification.APPROVED, metadata={"tools": []})

    first = check_invalidations(dep)
    events = ClaimEvent.objects.filter(claim__deployment=dep).count()
    second = check_invalidations(dep)

    assert first["retests_opened"] >= 1
    assert second["retests_opened"] == 0
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).count() == first["retests_opened"]
    assert ClaimEvent.objects.filter(claim__deployment=dep).count() == events


def test_a_re_derive_with_nothing_moved_writes_no_version_and_no_event():
    dep, _claim = _claimed_deployment()
    claims = AssuranceClaim.objects.filter(deployment=dep).count()
    events = ClaimEvent.objects.filter(claim__deployment=dep).count()

    again = derive_claims(dep)

    assert again["created"] == again["superseded"] == 0
    assert AssuranceClaim.objects.filter(deployment=dep).count() == claims
    assert ClaimEvent.objects.filter(claim__deployment=dep).count() == events


def test_a_persons_move_replayed_writes_one_event():
    dep, claim = _claimed_deployment()
    assert claim.status == ClaimStatus.VERIFIED
    client = _client(_user(User.Roles.ADMIN))
    url = f"/api/assurance/claims/{claim.uuid}/transition/"
    events = ClaimEvent.objects.filter(claim=claim).count()

    first = client.post(url, {"to_status": "supported", "note": "downgrade"}, format="json", **{KEY: "move-1"})
    replay = client.post(url, {"to_status": "supported", "note": "downgrade"}, format="json", **{KEY: "move-1"})

    assert first.status_code == 200
    assert replay.status_code == 400, "a replayed move was recorded a second time"
    assert ClaimEvent.objects.filter(claim=claim).count() == events + 1
    assert _access_claim(dep).status == ClaimStatus.SUPPORTED


def test_a_take_down_replayed_with_a_key_is_processed_again_and_moves_the_claim_once():
    """A revoke is a stop: it is processed every time it arrives, key or no key -- the
    second is recorded, attributed, on the claim ("already withdrawn") -- and the claim
    moved once."""
    dep, claim = _claimed_deployment()
    client = _client(_user(User.Roles.ADMIN))
    url = f"/api/assurance/claims/{claim.uuid}/transition/"

    for _ in range(2):
        response = client.post(url, {"to_status": "revoked"}, format="json", **{KEY: "revoke-1"})
        assert response.status_code == 200
        assert "Idempotent-Replayed" not in response

    events = ClaimEvent.objects.filter(claim=claim, to_status=ClaimStatus.REVOKED).order_by("pk")
    assert [(e.from_status, e.to_status) for e in events] == [
        (ClaimStatus.VERIFIED, ClaimStatus.REVOKED), (ClaimStatus.REVOKED, ClaimStatus.REVOKED),
    ]
    assert "already withdrawn" in events[1].note
    assert _access_claim(dep).status == ClaimStatus.REVOKED


def test_an_evidence_invalidation_replayed_is_refused_and_moves_the_claim_once():
    dep, claim = _claimed_deployment()
    admin = _user(User.Roles.ADMIN)
    item = record_claim_evidence(claim, **_evidence(claim))

    invalidate_claim_evidence(item, actor=admin, reason="named the wrong route")
    events = ClaimEvent.objects.filter(claim__deployment=dep).count()
    with pytest.raises(EvidenceRefused, match="already invalidated"):
        invalidate_claim_evidence(ClaimEvidence.objects.get(pk=item.pk), actor=admin, reason="named the wrong route")

    assert ClaimEvent.objects.filter(claim__deployment=dep).count() == events


def test_the_same_evidence_recorded_twice_moves_the_claim_once():
    """No caller records evidence yet (no route, no queue): recorded twice it is two
    items -- the audit trail says so -- and the claim reads, and moves, as it would on
    one. A future ingest path should key items on the claim and their content digest."""
    dep, claim = _claimed_deployment()
    adverse = _evidence(claim, outcome=ClaimVerdict.FAIL.value)

    record_claim_evidence(claim, **adverse)
    once = _access_claim(dep)
    events = ClaimEvent.objects.filter(claim__deployment=dep).count()
    record_claim_evidence(claim, **adverse)
    twice = _access_claim(dep)

    assert ClaimEvidence.objects.filter(deployment=dep).count() == 2
    assert (twice.pk, twice.status, twice.evidence_verdict) == (once.pk, once.status, once.evidence_verdict)
    assert ClaimEvent.objects.filter(claim__deployment=dep).count() == events


# ===========================================================================
# failsafe-drafts, engine-poll
# ===========================================================================

POLL_TOKEN = "test-poll-token-p4"


@pytest.fixture()
def failsafe(settings):
    from mythos_core.failsafe.sign import keygen

    private, public = keygen()
    settings.FAILSAFE_OPERATOR_KEYS = {"alice": public}
    settings.FAILSAFE_POLL_TOKEN = POLL_TOKEN
    settings.FAILSAFE_COMMAND_TTL_SECONDS = 600
    return private


def _sign(client, draft, private):
    from mythos_core.failsafe.sign import sign_draft

    fields = {k: draft[k] for k in ("action", "engine_id", "nonce", "issued_at", "expires_at", "reason")}
    return client.post(f"/api/failsafe/commands/{draft['uuid']}/signatures/",
                       sign_draft(fields, key_id="alice", private_hex=private), format="json")


def test_a_stop_draft_replayed_with_a_key_is_processed_each_time(failsafe):
    """The draft route is a stop route: a key there changes nothing. Once the first
    draft is signed, the same request with the same key is a NEW draft -- a record
    answering for it would have handed back the signed one."""
    client = _client(_user())
    body = {"action": "pause", "engine_id": "athena-1", "reason": "operator stop"}

    first = client.post("/api/failsafe/commands/", body, format="json", **{KEY: "stop-1"})
    assert first.status_code == 201
    assert _sign(client, first.json(), failsafe).status_code == 200
    again = client.post("/api/failsafe/commands/", body, format="json", **{KEY: "stop-1"})

    assert again.status_code == 201, again.content
    assert again.json()["uuid"] != first.json()["uuid"]
    assert FailsafeCommand.objects.filter(action="pause").count() == 2


def test_a_start_draft_replayed_is_two_unsigned_drafts_no_poll_serves(failsafe):
    client = _client(_user())
    body = {"action": "resume", "engine_id": "athena-1", "reason": "resume after review"}

    for _ in range(2):
        assert client.post("/api/failsafe/commands/", body, format="json").status_code == 201
    polled = APIClient().get("/api/failsafe/pending/", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)

    assert FailsafeCommand.objects.filter(action="resume", signed=False).count() == 2
    assert polled.status_code == 200 and polled.json() == []


def test_a_signed_command_polled_twice_is_one_nonce(failsafe):
    client = _client(_user())
    draft = client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-1"}, format="json")
    assert _sign(client, draft.json(), failsafe).json()["status"] == "ready"
    poller = APIClient()

    polls = [poller.get("/api/failsafe/pending/", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN).json() for _ in range(2)]

    assert [len(p) for p in polls] == [1, 1]
    assert polls[0][0]["nonce"] == polls[1][0]["nonce"] == draft.json()["nonce"]


# ===========================================================================
# scan-ingest
# ===========================================================================


def test_a_scan_ingested_twice_records_each_finding_once():
    analyst = _user()
    engagement = _engagement(analyst)
    scan = PentestScan.objects.create(user=analyst, engagement=engagement, target_url=TARGET, consent=True,
                                      status=PentestScan.STATUS_COMPLETED,
                                      engine_response=_recorded_scan_answer()["result"])

    first = ingest_scan(scan)
    findings = Finding.objects.count()
    second = ingest_scan(scan)

    assert first and {f.pk for f in first} == {f.pk for f in second}
    assert Finding.objects.count() == findings


# ===========================================================================
# SAFETY: a stop is never deduplicated
# ===========================================================================


def test_a_pause_replayed_with_a_key_is_processed_every_time():
    """Pause with a key, lift, pause again with the SAME key: the deployment is paused.
    A record answering the second pause would have left it running."""
    admin = _user(User.Roles.ADMIN)
    dep = _deployment(admin)
    client = _client(admin)
    url = f"/api/assurance/deployments/{dep.uuid}/recompute/"

    assert client.post(url, {"paused": True}, format="json", **{KEY: "pause"}).json()["decision"] == "paused"
    assert client.post(url, {"paused": False}, format="json").json()["decision"] != "paused"
    again = client.post(url, {"paused": True}, format="json", **{KEY: "pause"})

    assert again.status_code == 200 and again.json()["decision"] == "paused"
    assert "Idempotent-Replayed" not in again
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.PAUSED


def test_an_engagement_withdrawn_with_a_key_is_withdrawn_every_time():
    analyst = _user()
    engagement = _engagement(analyst)
    client = _client(analyst)
    url = f"/api/pentest/engagements/{engagement.pk}/"

    assert client.patch(url, {"status": "paused"}, format="json", **{KEY: "withdraw"}).status_code == 200
    assert client.patch(url, {"status": "running"}, format="json").status_code == 200
    again = client.patch(url, {"status": "paused"}, format="json", **{KEY: "withdraw"})

    assert again.status_code == 200 and "Idempotent-Replayed" not in again
    engagement.refresh_from_db()
    assert engagement.status == "paused"


def test_the_key_layer_is_never_on_a_stop_route():
    """Structurally: every route the layer is on is a real route and none is a stop,
    and the layer refuses, at import, to be put on one."""
    from django.core.exceptions import ImproperlyConfigured
    from django.urls import reverse
    from idempotency import layer
    from safety.stops import EXEMPT_ROUTES

    assert get_resolver().url_patterns  # every view module imported: the layer registers at import
    assert layer.ROUTES == {
        "pentest:run_pentest_scan", "pentest:run_llm_pentest_scan",
        "pentest:resend_scan_email", "deployment-connector-push",
    }
    assert not layer.ROUTES & set(EXEMPT_ROUTES)
    for route in EXEMPT_ROUTES:
        with pytest.raises(ImproperlyConfigured, match="stop"):
            layer.idempotent(route)
    kwargs = {"deployment-connector-push": {"uuid": uuid.uuid4(), "connector": "jira"},
              "pentest:resend_scan_email": {"scan_id": uuid.uuid4()}}
    for route in layer.ROUTES:
        reverse(route, kwargs=kwargs.get(route))


def test_the_key_layer_passes_a_request_on_a_stop_route_straight_through():
    """At run time too: a view the layer wraps that is reached on a stop route runs
    every time, reads no key and records nothing."""
    from idempotency import layer
    from idempotency.models import IdempotencyRecord
    from rest_framework.parsers import JSONParser
    from rest_framework.request import Request
    from rest_framework.response import Response

    admin = _user(User.Roles.ADMIN)
    dep = _deployment(admin)
    ran = []

    def view(request):
        ran.append(request.data)
        return Response({"ran": len(ran)})

    wrapped = layer.idempotent("pentest:resend_scan_email")(view)
    for _ in range(2):
        django_request = RequestFactory().post(f"/api/assurance/deployments/{dep.uuid}/recompute/",
                                               json.dumps({"paused": True}), content_type="application/json",
                                               **{KEY: "same"})
        request = Request(django_request, parsers=[JSONParser()])
        request.user = admin
        assert wrapped(request).data == {"ran": len(ran)}

    assert len(ran) == 2
    assert not IdempotencyRecord.objects.exists()


# ===========================================================================
# The matrix is complete, and every test it names exists
# ===========================================================================


def test_every_effect_boundary_in_the_code_is_in_the_matrix():
    """A new outbound write, e-mail, connector push, engine call that POSTs or durable
    row another process acts on fails here until it has a row in MATRIX -- and so a
    fire-twice test."""
    found = effect_sites()
    assert found - set(SITES) == set(), "effect call sites with no row in the matrix"
    assert set(SITES) - found == set(), "matrix rows naming call sites the code no longer has"
    assert set(SITES.values()) <= set(MATRIX)


def test_every_matrix_test_exists():
    here = globals()
    named = {name for boundary in MATRIX.values() for name in boundary.tests}
    assert all(callable(here.get(name)) for name in named), sorted(n for n in named if n not in here)
    for boundary in MATRIX.values():
        assert boundary.tests and all(field.strip() for field in boundary[:4])


def test_the_scan_reads_what_it_should():
    """The completeness scan itself, on code written to be found: a reference to
    requests.post counts even uncalled, an e-mail function's caller counts, and a
    read does not."""
    sources = {
        _CLIENT: "class CyberEngineClient:\n    def go(self):\n        return self._post('/x', {})\n",
        "app/a.py": "import requests\ndef f(h):\n    h(requests.post)\n    requests.get('u')\n",
        "app/b.py": "from django.core.mail import EmailMessage\ndef mailer():\n    EmailMessage().send()\n"
                    "def view(client):\n    mailer()\n    client.go()\n    Finding.objects.create()\n"
                    "    FailsafeCommand.objects.get_or_create()\n",
    }
    assert effect_sites(sources) == {
        "app/a.py::f::requests.post",
        "app/b.py::mailer::EmailMessage",
        "app/b.py::view::mailer",
        "app/b.py::view::go",
        "app/b.py::view::FailsafeCommand.objects.get_or_create",
    }
