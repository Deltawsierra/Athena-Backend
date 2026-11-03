"""No effect launches without the preflight (G14-AB-2; the owner's decision 13).

safety.degraded declares every route's operation class. An *effect* fails closed:
when what it depends on cannot be asked, it is held, never done. A launch -- the
engine aimed at a customer's system -- depends on the preflight
(ai_engine.services.preflight): the assurance gate, the extension review, the
unattributed effects and route attestation, asked of the engine before it is
pointed anywhere. The standard scan and the reconcile resend asked it;
``run_llm_pentest_scan`` asked nothing, so a deployment the gate would block, a
revoked extension or an engine that could not be asked launched an LLM red-team
run against a customer's model endpoint all the same.

Three sections:

* the sweep -- every effect route in safety.degraded says whether it launches, and
  each launch asks the preflight; one that does not launch says why the preflight
  is not its gate and what holds it instead;
* the launch sites -- every call that launches the engine is in a function named
  here, and each routed one asks the preflight first, in source order;
* the LLM scan's verdicts, driven through the route against a real client: an
  engine that refuses, hangs or answers garbage holds it (409) in every mode, a
  blocked verdict refuses under enforce and is recorded under observe, and a clean
  one launches with its verdict kept on the scan.
"""

from __future__ import annotations

import ast
import http.server
import threading
import time
from datetime import timedelta
from pathlib import Path
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from safety import degraded
from tests.test_every_operation_says_how_it_degrades import _engine
from tests.test_no_control_holds_back_a_stop import walk

ROOT = Path(__file__).resolve().parent.parent

# --- The sweep ------------------------------------------------------------------------

#: Aims the engine at a target. Asks the preflight first, and is held (409) on its
#: ``unknown`` in every mode and on ``blocked`` under enforce.
LAUNCH = "launches the engine at a target: asks the preflight first"

_ENGINE_READ = (
    "reads a run the engine already has and records it: it launches nothing, and refusing it on the "
    "preflight would leave a run that already happened unrecorded. An engine that cannot be read "
    "writes nothing (the scan stays pending; 503)"
)
_THIRD_PARTY = (
    "sends to a third party (a ticket system, a mail server), never to the engine: the preflight asks "
    "whether the engine is the approved deployment, which this does not depend on. Its own failure is "
    "recorded, failed or unknown and held, never sent twice as done"
)
_RECORD = (
    "writes this backend's own record and nothing else: no engine, no target, nothing for the preflight "
    "to ask about. A failed write fails closed (safety.degraded's HOLD: nothing proceeds)"
)
_SIGN_IN = "issues a token on a password: no engine, no target. A failed read fails closed (HOLD)"
_NOTHING = "returns a suggested plan and writes nothing: no engine, no target"

#: Every effect route and method in safety.degraded, and whether the preflight is its
#: gate. The admin site (safety.degraded.ADMIN_CLASS) writes this backend's own rows
#: only, as _RECORD says, and is not listed by name.
EFFECTS = {
    ("token_obtain_pair", "POST"): _SIGN_IN,
    ("accounts:user-list", "POST"): _RECORD,
    ("accounts:user-detail", "PUT"): _RECORD,
    ("accounts:user-detail", "PATCH"): _RECORD,
    ("claim-declare-latent-condition", "POST"): _RECORD,
    ("claim-withdraw-latent-condition", "POST"): _RECORD,
    ("deployment-chain-birth", "POST"): _RECORD,
    ("deployment-connector-push", "POST"): _THIRD_PARTY,
    ("deployment-connector-config", "PUT"): _RECORD,
    ("deployment-connector-config", "DELETE"): _RECORD,
    ("deployment-posture-config", "PUT"): _RECORD,
    ("deployment-posture-config", "DELETE"): _RECORD,
    ("deployment-data-boundary", "PUT"): _RECORD,
    ("deployment-data-boundary", "PATCH"): _RECORD,
    ("deployment-approved-workflows", "PUT"): _RECORD,
    ("deployment-chain-outcomes", "POST"): _RECORD,
    ("deployment-observed-chain-outcomes", "POST"): _RECORD,
    ("deployment-authority-chains", "POST"): _RECORD,
    ("deployment-observed-effects", "POST"): _RECORD,
    ("deployment-effect-reconciliations", "POST"): _RECORD,
    ("deployment-achilles-scan-results", "POST"): _RECORD,
    ("deployment-authentications", "POST"): _RECORD,
    ("deployment-delegations", "POST"): _RECORD,
    ("deployment-economics-parameter-set-versions", "POST"): _RECORD,
    ("deployment-economics-scenario-build", "POST"): _RECORD,
    ("economics-source-trust-raises", "POST"): _RECORD,
    ("economics-trust-raise-approve", "POST"): _RECORD,
    ("economics-trust-raise-withdraw", "POST"): _RECORD,
    ("deployment-economics-scenario-simulate", "POST"): _RECORD,
    ("deployment-economics-assurance", "POST"): _RECORD,
    ("deployment-economics-scenario-refresh", "POST"): _RECORD,
    ("deployment-economics-scenario-reviews", "POST"): _RECORD,
    ("deployment-economics-scenario-overrides", "POST"): _RECORD,
    ("deployment-economics-override-approve", "POST"): _RECORD,
    ("deployment-economics-scenario-mitigations", "POST"): _RECORD,
    ("deployment-economics-mitigation-simulate", "POST"): _RECORD,
    ("deployment-economics-portfolio-simulate", "POST"): _RECORD,
    ("deployment-economics-portfolio-groups", "POST"): _RECORD,
    ("deployment-legal-obligations", "POST"): _RECORD,
    ("deployment-legal-obligation-supersede", "POST"): _RECORD,
    ("deployment-declared-architecture", "PUT"): _RECORD,
    ("deployment-record-bom-drift", "POST"): _RECORD,
    ("finding-detail", "PUT"): _RECORD,
    ("finding-detail", "PATCH"): _RECORD,
    ("finding-remediation-transition", "POST"): _RECORD,
    ("finding-remediation-assign", "POST"): _RECORD,
    ("finding-closure-evidence", "POST"): _RECORD,
    ("finding-retest-checks-collect", "POST"): _ENGINE_READ,
    ("finding-repair-contracts", "POST"): _RECORD,
    ("finding-recovery-record", "POST"): _RECORD,
    ("provider-list", "POST"): _RECORD,
    ("provider-detail", "PUT"): _RECORD,
    ("provider-detail", "PATCH"): _RECORD,
    ("provider-assertion-list", "POST"): _RECORD,
    ("provider-assertion-detail", "PUT"): _RECORD,
    ("provider-assertion-detail", "PATCH"): _RECORD,
    ("provider-assertion-detail", "DELETE"): _RECORD,
    ("unknown-detail", "PUT"): _RECORD,
    ("unknown-detail", "PATCH"): _RECORD,
    ("detection:cve-email", "POST"): _THIRD_PARTY,
    ("pentest:run_pentest_scan", "POST"): LAUNCH,
    ("pentest:run_llm_pentest_scan", "POST"): LAUNCH,
    ("pentest:reconcile_pentest_scan", "POST"): LAUNCH,
    ("pentest:collect_pentest_scan", "POST"): _ENGINE_READ,
    ("pentest:resend_scan_email", "POST"): _THIRD_PARTY,
    ("pentest:engagements", "POST"): _RECORD,
    ("pentest:engagement_detail", "DELETE"): _RECORD,
    ("pentest:engagement_plan", "POST"): _NOTHING,
}


def test_every_effect_route_says_whether_the_preflight_is_its_gate():
    """A new effect route cannot be added without somebody deciding whether it launches."""
    declared = {
        (name, method)
        for name, methods in degraded.ROUTES.items()
        for method, klass in methods.items()
        if klass == degraded.EFFECT
    }
    assert set(EFFECTS) == declared, {
        "an effect with no word on the preflight": sorted(declared - set(EFFECTS)),
        "named here, not an effect": sorted(set(EFFECTS) - declared),
    }
    assert degraded.ADMIN_CLASS == degraded.EFFECT


# --- Every launch site, and the preflight before it -------------------------------------

#: The engine calls that launch: each aims the engine at a target.
LAUNCH_CALLS = ("run_scan", "run_llm_scan")

#: Every function that makes a launch call, and how it is reached.
LAUNCH_SITES = {
    # The standard scan's launch, sent by the two routes below, each after the preflight.
    "pentest/views.py::_send_launch": ("run_pentest_scan", "reconcile_pentest_scan"),
    "pentest/views.py::run_llm_pentest_scan": ("run_llm_pentest_scan",),
    # The unrouted PentestLLMScanView (pentest/views_llm.py) launched with no preflight
    # and is deleted; tests/test_no_launch_path_skips_the_preflight.py refuses any
    # launch path, routed or not, that does not pass through the preflight.
}

#: The route of each view that launches, by URL name.
LAUNCH_ROUTES = {
    "run_pentest_scan": "pentest:run_pentest_scan",
    "reconcile_pentest_scan": "pentest:reconcile_pentest_scan",
    "run_llm_pentest_scan": "pentest:run_llm_pentest_scan",
}


def _source_files():
    for path in sorted(ROOT.rglob("*.py")):
        parts = path.relative_to(ROOT).parts
        if parts[0] in {"tests", "frontend", "node_modules"} or "migrations" in parts or parts[0].startswith("."):
            continue
        if "settings" in path.name.lower():
            continue  # settings files are never read here
        yield path


def _functions(tree):
    """(qualified name, node) for every function, methods as Class.method."""
    out = []

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append((prefix + child.name, child))
                visit(child, prefix + child.name + ".")
            elif isinstance(child, ast.ClassDef):
                visit(child, prefix + child.name + ".")

    visit(tree, "")
    return out


def _calls(node, attr):
    """Line numbers of every call of ``attr`` (as a name or an attribute) in ``node``'s own
    body: a function or class defined inside it is its own site, not this one."""
    lines = []
    stack = list(ast.iter_child_nodes(node))
    while stack:
        sub = stack.pop()
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(sub, ast.Call):
            func = sub.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == attr:
                lines.append(sub.lineno)
        stack.extend(ast.iter_child_nodes(sub))
    return lines


def _launch_sites():
    sites = {}
    for path in _source_files():
        rel = path.relative_to(ROOT).as_posix()
        if rel == "ai_engine/services/cyberengine_client.py":
            continue  # the client itself, which defines the calls
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for qualname, node in _functions(tree):
            if any(_calls(node, call) for call in LAUNCH_CALLS):
                sites[f"{rel}::{qualname}"] = node
    return sites


def test_every_launch_site_is_named():
    assert sorted(_launch_sites()) == sorted(LAUNCH_SITES)


def _views():
    tree = ast.parse((ROOT / "pentest" / "views.py").read_text(encoding="utf-8"))
    return dict(_functions(tree))


def test_every_routed_launch_asks_the_preflight_before_it_launches():
    """The preflight's check is called in the view, and before the launch, in source
    order: a check after the launch is not a gate."""
    views = _views()
    problems = []
    for site, routed_from in LAUNCH_SITES.items():
        _path, qualname = site.split("::")
        for view in routed_from:
            node = views[view]
            checks = _calls(node, "check")
            launches = [line for call in (*LAUNCH_CALLS, qualname) for line in _calls(node, call)]
            if not launches:
                problems.append(f"{view}: does not reach {site}")
            elif not checks or min(checks) > min(launches):
                problems.append(f"{view}: launches (line {min(launches)}) with no preflight.check before it")
    assert problems == [], problems


def test_the_standard_launch_is_sent_only_by_routes_that_ask_the_preflight():
    callers = sorted(name for name, node in _views().items() if _calls(node, "_send_launch"))
    assert callers == sorted(LAUNCH_SITES["pentest/views.py::_send_launch"])


def test_every_launching_view_is_the_route_it_is_named_for():
    served = walk()
    for view, route in LAUNCH_ROUTES.items():
        assert route in served, route
        assert degraded.class_of(route, "POST") == degraded.EFFECT
        assert EFFECTS[(route, "POST")] == LAUNCH


# --- The LLM scan, driven through its route -----------------------------------------------


@pytest.fixture()
def admin(db):
    return get_user_model().objects.create_user(
        username="ab2-admin", password="x", role="admin", is_staff=True, is_superuser=True
    )


@pytest.fixture()
def engagement(admin):
    from pentest.models import Engagement

    now = timezone.now()
    return Engagement.objects.create(
        created_by=admin, name="AB-2", status="running", scope_hosts=["client.example"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )


@pytest.fixture()
def engine_at():
    servers = []

    def start(handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _fresh_preflight():
    from ai_engine.services import preflight

    preflight.clear_cache()
    yield
    preflight.clear_cache()


LLM_SCAN = "/api/pentest/llm-scan/"


def _body(engagement):
    return {
        "base_url": "https://client.example/v1/chat/completions",
        "adapter": "openai_style",
        "attacks": ["metaprompt_extraction"],
        "max_turns": 2,
        "consent": True,
        "engagement_id": engagement.pk,
    }


def _post(admin, engagement, client, gate_mode, *, launch=None):
    from ai_engine.services import cyberengine_client, preflight

    api = APIClient(raise_request_exception=False)
    api.force_authenticate(user=admin)
    run = launch or mock.Mock(side_effect=AssertionError("launched"))
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as factory, \
            mock.patch.object(cyberengine_client, "ENGINE_TIMEOUT", (0.3, 0.3)), \
            mock.patch.object(preflight, "mode", return_value=gate_mode), \
            mock.patch.object(type(client), "run_llm_scan", run), \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"):
        factory.from_settings.return_value = client
        response = api.post(LLM_SCAN, _body(engagement), format="json")
    return response, run


@pytest.mark.django_db
@pytest.mark.parametrize("gate_mode", ["observe", "enforce"])
@pytest.mark.parametrize("fault", ["raises", "hangs", "malformed"])
def test_an_llm_scan_whose_engine_could_not_be_asked_is_held_in_every_mode(
    admin, engagement, engine_at, fault, gate_mode
):
    """The engine refusing connections, hanging past its read timeout, or answering an
    HTML holding page: the preflight's verdict is ``unknown``, and the LLM scan is held
    (409) under observe as under enforce. Nothing is launched and no scan is recorded."""
    from pentest.models import PentestScan

    client = _engine(fault, engine_at)
    started = time.monotonic()
    response, run = _post(admin, engagement, client, gate_mode)
    assert time.monotonic() - started < 10
    assert response.status_code == 409, response.content
    body = response.json()
    assert body["error"].startswith("This engine is not the deployment that was approved: held, not launched")
    assert body["assurance"]["verdict"] == "unknown"
    assert not run.called
    assert not PentestScan.objects.exists()


class _Answers:
    """An engine whose preflight answers are ``verdict`` for the assurance gate, and
    clean for the rest; ``run_llm_scan`` is patched in by ``_post``."""

    def __init__(self, verdict):
        self.verdict = verdict

    def assurance_check(self, *_args, **_kwargs):
        return {"verdict": self.verdict, "detail": f"the gate said {self.verdict}"}

    def extension_review(self):
        return {"review": {"verdict": "ok"}}

    def unattributed_effects(self, limit=25):
        return {"effects": []}

    def attestation_check(self, *_args, **_kwargs):
        return {"verdict": "unchanged"}

    def run_llm_scan(self, payload):  # replaced by _post
        raise AssertionError("not patched")


@pytest.mark.django_db
def test_an_llm_scan_the_gate_blocks_is_refused_under_enforce(admin, engagement):
    from pentest.models import PentestScan

    response, run = _post(admin, engagement, _Answers("blocked"), "enforce")
    assert response.status_code == 409, response.content
    assert response.json()["assurance"]["verdict"] == "blocked"
    assert not run.called
    assert not PentestScan.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize(("verdict", "recorded"), [("blocked", "blocked"), ("unchanged", "review")])
def test_an_llm_scan_the_gate_answered_launches_with_its_verdict_recorded(admin, engagement, verdict, recorded):
    """Observe keeps its meaning for an answer the gate could read: a blocked verdict is
    recorded and the scan proceeds, as the standard scan's does. The verdict is kept on
    the scan, next to the work it governed."""
    from pentest.models import PentestScan

    launch = mock.Mock(return_value={"results": [{"type": "info"}]})
    response, run = _post(admin, engagement, _Answers(verdict), "observe", launch=launch)
    assert response.status_code == 200, response.content
    assert run.call_count == 1
    scan = PentestScan.objects.get()
    assert scan.assurance["verdict"] == recorded
    assert scan.status == PentestScan.STATUS_COMPLETED
