"""No launch path skips the preflight, routed or not (AB-DEADVIEW).

``pentest/views_llm.py`` held ``PentestLLMScanView``: an LLM red-team launch with no
preflight, no consent check and no target bounds. No URL named it, so nothing could
reach it -- until a later URL change did. It is deleted, and this file refuses any
launch path, routed or not, that does not pass through the preflight
(ai_engine.services.preflight: the assurance gate, the extension review, the
unattributed effects and route attestation, asked before the engine is aimed
anywhere).

It reads every first-party module (not the tests, the frontend, the migrations or a
settings file) and finds every place that can start a scan on the engine:

* the client's launch calls, ``run_scan`` and ``run_llm_scan`` -- called, held as a
  bound method, or named in a string (``getattr(client, "run_llm_scan")``);
* the engine's launch routes, ``/api/scan`` and ``/api/llm-scan``, named in a string
  (a POST that goes round the client).

The client's own two launch methods, which define the calls, are the only places
exempt. Every other place passes one of two ways:

* **it asks first** -- the function it is in calls ``preflight.check(...)`` as a
  statement of its own body (or of a ``try`` that is one), before the statement
  that launches; not under an ``if``, a loop or a ``with``, and every ``except`` of
  that ``try`` ends by returning or raising, so a refusal cannot fall through to the
  launch;
* **or it is reached only from places that ask first** -- it is a private
  module-level helper (``_send_launch``), referenced at least once, and every
  reference to it passes this same rule.

Anything else fails, whether a URL reaches it or not: a method (a view's ``post``,
which a dispatch calls by name), a public function, a nested function or lambda,
code at module or class level. The rule is checked against hand-written cases first,
so it cannot pass by finding nothing.
"""

from __future__ import annotations

import ast
import importlib.util
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: The client's calls that aim the engine at a target.
LAUNCH_CALLS = frozenset({"run_scan", "run_llm_scan"})
#: The engine's routes those calls POST to.
LAUNCH_ROUTES = ("/api/scan", "/api/llm-scan")
#: Where the launch calls are defined: their own bodies are the launch, not a path to it.
CLIENT = "ai_engine/services/cyberengine_client.py"

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_FUNCTIONS, ast.Lambda)
_TRIES = tuple(t for t in (ast.Try, getattr(ast, "TryStar", None)) if t is not None)


# --- Reading the code -------------------------------------------------------------------


def first_party_sources():
    """{relative path: source} for every module of this backend's own code."""
    sources = {}
    for path in sorted(ROOT.rglob("*.py")):
        parts = path.relative_to(ROOT).parts
        if parts[0] in {"tests", "frontend", "node_modules"} or "migrations" in parts:
            continue
        if any(part.startswith(".") for part in parts) or "site-packages" in parts:
            continue
        if "settings" in path.name.lower():
            continue  # settings files are never read here
        sources[path.relative_to(ROOT).as_posix()] = path.read_text(encoding="utf-8")
    return sources


class _Module:
    """One parsed module: each node's innermost enclosing function, each function's
    qualified name, and the docstrings (prose, never a reference)."""

    def __init__(self, rel, source):
        self.rel = rel
        self.tree = ast.parse(source)
        self.scope = {}  # node -> innermost function or lambda holding it (None: module/class level)
        self.qualname = {}  # function or lambda -> qualified name
        self.toplevel = {}  # function -> True when defined directly in the module
        self.docstrings = set()
        self._visit(self.tree, None, "")

    def _visit(self, node, scope, prefix):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.ClassDef, *_FUNCTIONS)) and body:
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                self.docstrings.add(first.value)
        for child in ast.iter_child_nodes(node):
            self.scope[child] = scope
            if isinstance(child, _FUNCTIONS):
                self.qualname[child] = prefix + child.name
                self.toplevel[child] = isinstance(node, ast.Module)
                self._visit(child, child, prefix + child.name + ".")
            elif isinstance(child, ast.Lambda):
                self.qualname[child] = f"{prefix}<lambda line {child.lineno}>"
                self.toplevel[child] = False
                self._visit(child, child, prefix)
            elif isinstance(child, ast.ClassDef):
                self._visit(child, scope, prefix + child.name + ".")
            else:
                self._visit(child, scope, prefix)

    def where(self, node):
        scope = self.scope.get(node)
        name = self.qualname[scope] if scope is not None else "<module or class level>"
        return f"{self.rel}::{name} (line {node.lineno})"

    def in_a_launch_definition(self, node):
        """Inside the client's own run_scan or run_llm_scan: the launch itself."""
        if self.rel != CLIENT:
            return False
        scope = self.scope.get(node)
        while scope is not None:
            if isinstance(scope, _FUNCTIONS) and scope.name in LAUNCH_CALLS:
                return True
            scope = self.scope.get(scope)
        return False

    def references(self, names, *, strings=True):
        """Every Name, attribute and (outside docstrings) string constant naming one of
        ``names``, as (node, the name)."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and node.id in names:
                yield node, node.id
            elif isinstance(node, ast.Attribute) and node.attr in names:
                yield node, node.attr
            elif (
                strings and isinstance(node, ast.Constant) and isinstance(node.value, str)
                and node not in self.docstrings and node.value.strip() in names
            ):
                yield node, node.value.strip()

    def launch_routes(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node not in self.docstrings:
                if node.value.strip().rstrip("/").endswith(LAUNCH_ROUTES):
                    yield node, node.value.strip()


def _is_preflight_check(node):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "check"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "preflight"
    )


def _asks_the_preflight(statement):
    """``statement`` is ``preflight.check(...)``, ``x = preflight.check(...)``, or a try
    whose body has one of those and whose every except ends by returning or raising."""
    if isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)):
        return _is_preflight_check(statement.value)
    if isinstance(statement, _TRIES):
        return any(_asks_the_preflight(s) for s in statement.body) and all(
            handler.body and isinstance(handler.body[-1], (ast.Return, ast.Raise)) for handler in statement.handlers
        )
    return False


def _asks_first(function, node):
    """``function`` asks the preflight in a statement of its own body before the one
    holding ``node``. A lambda has no statements: it never does."""
    if not isinstance(function, _FUNCTIONS):
        return False
    for statement in function.body:
        if any(sub is node for sub in ast.walk(statement)):
            return False
        if _asks_the_preflight(statement):
            return True
    return False


def unguarded_launch_paths(sources):
    """Why each launch path in ``sources`` ({relative path: source}) does not pass
    through the preflight, as sentences; [] when every one does."""
    modules = [_Module(rel, source) for rel, source in sources.items()]
    problems = []
    #: (module, function) that launch, or reach a launch, without asking first.
    launching = {}

    def note(module, node, what):
        scope = module.scope.get(node)
        if scope is not None and _asks_first(scope, node):
            return
        if scope is None:
            problems.append(f"{module.where(node)}: {what} at module or class level, where nothing can ask first")
            return
        launching.setdefault((module.rel, module.qualname[scope]), (module, scope, f"{what} at line {node.lineno}"))

    for module in modules:
        for node, name in module.references(LAUNCH_CALLS):
            if not module.in_a_launch_definition(node):
                note(module, node, f"names {name}")
        for node, route in module.launch_routes():
            if not module.in_a_launch_definition(node):
                note(module, node, f"names the engine's launch route {route!r}")

    # Every private helper that launches makes each place that references it a launch
    # path too, until nothing new is reached.
    done = set()
    while set(launching) - done:
        for key in sorted(set(launching) - done):
            done.add(key)
            module, function, _why = launching[key]
            if not (isinstance(function, _FUNCTIONS) and module.toplevel[function] and function.name.startswith("_")):
                continue
            for other in modules:
                for node, _name in other.references({function.name}):
                    if other.scope.get(node) is not function:
                        note(other, node, f"reaches {key[1]} ({module.rel})")

    # A private helper passes when something references it and every reference is one
    # that asks first, or sits in a helper that passes: least fixpoint, so helpers that
    # only reach each other never pass each other.
    def references_to(module, function):
        out = []
        for other in modules:
            for node, _name in other.references({function.name}):
                scope = other.scope.get(node)
                if scope is not function:
                    out.append((other, scope, node))
        return out

    passing = set()
    changed = True
    while changed:
        changed = False
        for key, (module, function, _why) in launching.items():
            if key in passing or not isinstance(function, _FUNCTIONS) or not module.toplevel[function]:
                continue
            if not function.name.startswith("_"):
                continue
            refs = references_to(module, function)
            if refs and all(
                scope is not None
                and (_asks_first(scope, node) or (other.rel, other.qualname[scope]) in passing)
                for other, scope, node in refs
            ):
                passing.add(key)
                changed = True

    for key in sorted(set(launching) - passing):
        module, function, why = launching[key]
        if isinstance(function, _FUNCTIONS) and module.toplevel[function] and function.name.startswith("_"):
            how = "and is not reached only from code that asks the preflight first"
        else:
            how = "with no preflight.check before it in its own body"
        problems.append(f"{key[0]}::{key[1]}: {why}, {how}")
    return sorted(set(problems))


def launch_sites(sources):
    """'path::function' of every function that names a launch call or route itself."""
    sites = set()
    for rel, source in sources.items():
        module = _Module(rel, source)
        for node, _name in [*module.references(LAUNCH_CALLS), *module.launch_routes()]:
            scope = module.scope.get(node)
            if scope is not None and not module.in_a_launch_definition(node):
                sites.add(f"{rel}::{module.qualname[scope]}")
    return sites


# --- The rule, against hand-written cases -------------------------------------------------

_CAUGHT = {
    "a view's post with no preflight (the deleted PentestLLMScanView)": """
        class LLMScanView(APIView):
            def post(self, request):
                client = CyberEngineClient()
                return client.run_llm_scan(request.data)
    """,
    "the preflight asked after the launch": """
        def view(client):
            answer = client.run_llm_scan({})
            preflight.check(client, tenant_id=None)
            return answer
    """,
    "the preflight asked only on one branch": """
        def view(client, strict):
            if strict:
                preflight.check(client, tenant_id=None)
            return client.run_llm_scan({})
    """,
    "a refusal swallowed": """
        def view(client):
            try:
                preflight.check(client, tenant_id=None)
            except preflight.DeploymentNotApproved:
                pass
            return client.run_llm_scan({})
    """,
    "some other check": """
        def view(client):
            gate.check(client)
            return client.run_llm_scan({})
    """,
    "the launch named in a string, for getattr": """
        def view(client):
            return getattr(client, "run_llm_scan")({})
    """,
    "the launch held as a bound method before the preflight": """
        def view(client):
            launch = client.run_llm_scan
            preflight.check(client, tenant_id=None)
            return launch({})
    """,
    "the engine's LLM route posted round the client": """
        def view(client):
            return outbound.post(client.base_url + "/api/llm-scan", json={}, engine=True)
    """,
    "the engine's scan route posted round the client": """
        def view(client):
            return outbound.post(f"{client.base_url}/api/scan", json={}, engine=True)
    """,
    "a launch at module level": """
        launch = CyberEngineClient().run_llm_scan
    """,
    "a launch in a nested function returned past the preflight": """
        def view(client):
            preflight.check(client, tenant_id=None)
            def later():
                return client.run_llm_scan({})
            return later
    """,
    "a launch in a lambda": """
        def view(client):
            preflight.check(client, tenant_id=None)
            return lambda: client.run_llm_scan({})
    """,
    "a private helper reached from a view that does not ask": """
        def _launch(client):
            return client.run_llm_scan({})

        def view(client):
            return _launch(client)
    """,
    "a private helper one of two callers reaches without asking": """
        def _launch(client):
            return client.run_scan("https://client.example")

        def asks(client):
            preflight.check(client, tenant_id=None)
            return _launch(client)

        def does_not(client):
            return _launch(client)
    """,
    "a private helper nothing references": """
        def _launch(client):
            return client.run_llm_scan({})
    """,
    "private helpers that only reach each other": """
        def _one(client):
            _two(client)
            return client.run_llm_scan({})

        def _two(client):
            return _one(client)
    """,
    "a launch call in the client outside its own definition": """
        class CyberEngineClient:
            def run_llm_scan(self, payload):
                return self._post("/api/llm-scan", payload)

            def quick_llm_scan(self, payload):
                return self.run_llm_scan(payload)
    """,
}

_PASSES = {
    "asked, and a refusal returns": """
        def view(client):
            try:
                assurance = preflight.check(client, tenant_id=None)
            except preflight.DeploymentNotApproved as refusal:
                return refusal
            return client.run_llm_scan({"assurance": assurance})
    """,
    "asked, and a refusal propagates": """
        def view(client):
            preflight.check(client, tenant_id=None)
            return client.run_llm_scan({})
    """,
    "a private helper every caller reaches after asking": """
        def _launch(client):
            return client.run_scan("https://client.example")

        def view(client):
            try:
                preflight.check(client, tenant_id=None)
            except preflight.DeploymentNotApproved:
                raise
            return _launch(client)
    """,
    "the client's own launch methods": """
        class CyberEngineClient:
            def run_llm_scan(self, payload):
                return self._post("/api/llm-scan", payload)

            def run_scan(self, target):
                return self._post("/api/scan", {"target": target})
    """,
    "prose that names the calls": '''
        def view(client):
            """Unlike run_llm_scan, this reads /api/scans/<id> and launches nothing."""
            return client.scan_status(f"/api/scans/{client.run_id}")
    ''',
}


@pytest.mark.parametrize("case", sorted(_CAUGHT))
def test_the_rule_refuses_each_way_round_the_preflight(case):
    rel = CLIENT if "client outside" in case else "pentest/example.py"
    problems = unguarded_launch_paths({rel: textwrap.dedent(_CAUGHT[case])})
    assert problems, f"not caught: {case}"


@pytest.mark.parametrize("case", sorted(_PASSES))
def test_the_rule_passes_a_launch_that_asks_first(case):
    rel = CLIENT if "client's own" in case else "pentest/example.py"
    assert unguarded_launch_paths({rel: textwrap.dedent(_PASSES[case])}) == []


# --- This backend ---------------------------------------------------------------------------


def test_no_launch_path_in_this_backend_skips_the_preflight():
    """Every place in this backend's code that can start a scan on the engine passes
    through the preflight first, whether a URL reaches it or not."""
    sources = first_party_sources()
    assert unguarded_launch_paths(sources) == []


def test_the_rule_reads_the_launches_there_are():
    """Not vacuous: the scan reads pentest/ and finds the two launches it guards."""
    sources = first_party_sources()
    assert "pentest/views.py" in sources and CLIENT in sources
    assert launch_sites(sources) >= {"pentest/views.py::_send_launch", "pentest/views.py::run_llm_pentest_scan"}


def test_the_unguarded_llm_view_is_gone():
    assert importlib.util.find_spec("pentest.views_llm") is None
    assert importlib.util.find_spec("pentest.serializers_llm") is None
