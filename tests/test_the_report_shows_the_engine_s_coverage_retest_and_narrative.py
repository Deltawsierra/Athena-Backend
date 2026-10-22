"""The customer PDF shows the engine's real coverage manifest, retest status and
persona narrative -- the three fields the report used to stand in for with
hardcoded text.

``report_mythos`` renders two editions (obsidian default, print) from
``scan.engine_response`` with no other context -- ``pentest.views`` calls
``render_scan_pdf_bytes(scan)`` with none -- so these read straight off
``engine_response``:

  * the coverage manifest at ``engine_response["coverage"]`` (the
    ``engine.coverage`` resolve shape: performed / degraded / not_performed /
    unmeasured, each with the engine's own reason) -- replacing a hardcoded
    capability list that implied coverage the scan never verified;
  * each finding's retest status at its ``retest_status`` (the engine charter
    field; ``"none"`` or absent -> the honest neutral "Not retested") --
    replacing a hardcoded "Planned";
  * each finding's additive ``narrative`` (the key the merged dashboard
    ``FindingNarrative`` reads; present only when the engine's report-voice flag
    is on), rendered as escaped text.

Each is additive and default-safe: a scan carrying none renders exactly as before
(or the honest neutral) and never crashes. weasyprint is stubbed through
``sys.modules``, as tests/test_a_referenced_standard_is_not_a_badge.py does; the
stub captures the one HTML document ``render_scan_pdf_bytes_html`` builds so the
whole assembly of both editions is exercised without rendering a PDF.
"""
from __future__ import annotations

import ast
import importlib
import pathlib
import sys
import types

import pytest


@pytest.fixture
def report(monkeypatch):
    captured: dict[str, str] = {}

    class _HTML:
        def __init__(self, string=None, base_url=None):
            captured["doc"] = string

        def write_pdf(self):
            return b"%PDF-1.4 stub"

    stub = types.ModuleType("weasyprint")
    stub.HTML = _HTML
    monkeypatch.setitem(sys.modules, "weasyprint", stub)
    monkeypatch.delitem(sys.modules, "pentest.report_mythos", raising=False)
    mod = importlib.import_module("pentest.report_mythos")
    mod._captured_doc = captured  # the last document render_scan_pdf_bytes_html built
    return mod


# --- Fixtures of what an engine emits --------------------------------------

#: A real coverage manifest, the engine.coverage resolve shape: a performed set,
#: and -- the honesty of it -- the degraded / not-performed / unmeasured checks
#: each with the engine's own reason, plus a run-level note.
_COVERAGE = {
    "complete": False,
    "checks": [
        {"check": "sql_injection", "team": "blue", "state": "performed", "probes_attempted": 14, "probes_failed": 0},
        {"check": "xss", "team": "blue", "state": "performed"},
        {"check": "command_injection", "team": "blue", "state": "performed"},
        {"check": "tls", "team": "blue", "state": "not_performed", "reason": "precondition",
         "detail": "The TLS scanner returns nothing against an http:// target."},
        {"check": "idor", "team": "blue", "state": "not_performed", "reason": "precondition",
         "detail": "IDOR needs two identities; only one was configured."},
        {"check": "header_scanner", "team": "blue", "state": "degraded", "probes_attempted": 9, "probes_failed": 4},
        {"check": "prompt_injection", "team": "red", "state": "unmeasured"},
    ],
    "not_performed": ["idor", "tls"],
    "degraded": ["header_scanner"],
    "unmeasured": ["prompt_injection"],
    "limitations": {},
    "notes": ["Surface discovery could not read the whole site."],
}

#: An engine's persona narrative: a blank line to keep, and quotes, an angle
#: bracket, an ampersand and a percent sign that must come back as text.
_NARRATIVE = (
    "In plain words: the sign-in form builds its database question from what is typed in.\n\n"
    "What was not tested: the reset flow. Wording that must survive: <b>bold</b> & 100%."
)

#: A real retest result the engine recorded on the finding (never the fabricated
#: "Planned", and -- per the engine charter -- never "fixed").
_RETEST = "Re-tested 2026-10-20: still present"

#: A fragment of BOTH editions' hardcoded capability lists, the thing the real
#: manifest replaces.
_HARDCODED = "Transport & headers"


def _finding(**over):
    f = {
        "type": "sql_injection",
        "severity": "high",
        "signature_description": "SQL injection in the sign-in form",
        "message": "the id parameter is injectable",
        "signature_recommendation": "Use parameterised queries.",
    }
    f.update(over)
    return f


def _scan(engine_response):
    return types.SimpleNamespace(engine_response=engine_response)


def _ctx(report, engine_response, variant="obsidian"):
    return report._extract(_scan(engine_response), {"variant": variant})


def _full_doc(report, engine_response, variant="obsidian"):
    context = {"variant": "print"} if variant == "print" else None
    pdf = report.render_scan_pdf_bytes_html(_scan(engine_response), context)
    assert pdf == b"%PDF-1.4 stub"
    return report._captured_doc["doc"]


# ===========================================================================
# Fix 1 -- the coverage manifest replaces the hardcoded capability list.
# obsidian `_profile`, print `_p_profile`.
# ===========================================================================


@pytest.mark.parametrize("builder,variant", [("_profile", "obsidian"), ("_p_profile", "print")])
def test_a_scan_with_a_coverage_manifest_shows_what_ran_and_what_did_not(report, builder, variant):
    page = getattr(report, builder)(_ctx(report, {"results": [_finding()], "coverage": _COVERAGE}, variant))
    # What was performed, named from the engine's own check names.
    assert "SQL Injection" in page
    assert "Command Injection" in page
    # The honesty: what was NOT performed / degraded / unmeasured, with reasons.
    assert "Not performed" in page and "TLS" in page
    assert "two identities" in page  # the engine's own not-performed detail
    assert "Degraded" in page and "Header Scanner" in page
    assert "4 of 9 probes lost" in page
    assert "Coverage not measured" in page and "Prompt Injection" in page
    assert "Surface discovery could not read the whole site." in page  # a run-level note
    # and the hardcoded list it replaces is gone on a scan that carried a manifest.
    assert _HARDCODED not in page


@pytest.mark.parametrize("builder,variant", [("_profile", "obsidian"), ("_p_profile", "print")])
def test_a_scan_without_a_coverage_manifest_keeps_todays_capability_list(report, builder, variant):
    page = getattr(report, builder)(_ctx(report, {"results": [_finding()]}, variant))
    assert _HARDCODED in page  # legacy behaviour preserved, not crashed
    assert "Not performed" not in page  # and nothing fabricated


def test_a_complete_manifest_says_nothing_was_left_untested(report):
    cov = {"complete": True, "notes": [], "checks": [
        {"check": "sql_injection", "team": "blue", "state": "performed"},
        {"check": "xss", "team": "blue", "state": "performed"}]}
    page = report._profile(_ctx(report, {"results": [], "coverage": cov}))
    assert "nothing in the engine's catalogue was left untested" in page


@pytest.mark.parametrize("bad", ["", [], 0, {"checks": "nope"}, {"checks": []}, {"no": "checks"}])
def test_an_unusable_coverage_value_degrades_to_the_legacy_list(report, bad):
    page = report._profile(_ctx(report, {"results": [_finding()], "coverage": bad}))
    assert _HARDCODED in page  # treated as absent, never a crash


# ===========================================================================
# Fix 2 -- the real retest status replaces the hardcoded "Planned".
# print `_p_remediation` Status column; obsidian `_remediation` Retest column.
# ===========================================================================


def test_the_print_remediation_shows_the_real_retest_status_not_planned(report):
    page = report._p_remediation(_ctx(report, {"results": [_finding(retest_status=_RETEST)]}, "print"))
    assert _RETEST in page
    assert "Planned" not in page


def test_the_print_remediation_without_a_record_says_not_retested_not_planned(report):
    page = report._p_remediation(_ctx(report, {"results": [_finding()]}, "print"))
    assert "Not retested" in page
    assert "Planned" not in page


def test_a_retest_status_of_none_is_the_honest_neutral(report):
    page = report._p_remediation(_ctx(report, {"results": [_finding(retest_status="none")]}, "print"))
    assert "Not retested" in page


def test_the_obsidian_remediation_carries_the_real_retest_status_too(report):
    told = report._remediation(_ctx(report, {"results": [_finding(retest_status=_RETEST)]}))
    assert "Retest" in told  # the column header
    assert _RETEST in told
    untold = report._remediation(_ctx(report, {"results": [_finding()]}))
    assert "Not retested" in untold
    assert "Planned" not in untold


# ===========================================================================
# Fix 3 -- the additive persona narrative, when present.
# obsidian `_findings`, print `_p_evidence`.
# ===========================================================================


def test_the_narrative_appears_in_the_obsidian_findings_when_present(report):
    page = report._findings(_ctx(report, {"results": [_finding(narrative=_NARRATIVE)]}))
    assert "In plain words: the sign-in form" in page
    assert "What was not tested: the reset flow." in page
    # The signature description and message are kept, not replaced by it.
    assert "SQL injection in the sign-in form" in page
    assert "the id parameter is injectable" in page


def test_the_narrative_appears_in_the_print_evidence_when_present(report):
    page = report._p_evidence(_ctx(report, {"results": [_finding(narrative=_NARRATIVE)]}, "print"))
    assert "In plain words: the sign-in form" in page


def test_a_finding_without_a_narrative_gets_no_narrative_block(report):
    obsidian = report._findings(_ctx(report, {"results": [_finding()]}))
    assert "fv-narr" not in obsidian
    assert "Narrative" not in obsidian
    printed = report._p_evidence(_ctx(report, {"results": [_finding()]}, "print"))
    assert "ev-narr" not in printed


def test_the_narrative_is_escaped_as_text_never_html(report):
    page = report._findings(_ctx(report, {"results": [_finding(narrative=_NARRATIVE)]}))
    assert "<b>bold</b>" not in page  # the raw tag must never reach the document
    assert "&lt;b&gt;bold&lt;/b&gt;" in page  # escaped instead


# ===========================================================================
# Default-safe: the full render of BOTH editions assembles without crashing,
# with the fields present and with them absent.
# ===========================================================================


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_the_full_report_renders_without_a_manifest_retest_or_narrative(report, variant):
    doc = _full_doc(report, {"results": [_finding(), {"type": "xss", "severity": "low"}]}, variant)
    assert _HARDCODED in doc  # the legacy capability list (no manifest on this scan)
    assert "Not retested" in doc  # the retest fallback, never a fabricated status
    assert "Planned" not in doc


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_the_full_report_renders_the_manifest_retest_and_narrative_when_present(report, variant):
    engine = {"results": [_finding(narrative=_NARRATIVE, retest_status=_RETEST)], "coverage": _COVERAGE}
    doc = _full_doc(report, engine, variant)
    assert "Not performed" in doc and "TLS" in doc
    assert _RETEST in doc
    assert "In plain words: the sign-in form" in doc
    assert _HARDCODED not in doc


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_an_empty_engine_response_still_renders(report, variant):
    assert _full_doc(report, {}, variant)  # no results, no coverage: still a document


# ===========================================================================
# No signed/receipt/evidence-pack artefact is read or written: the renderer
# consumes engine_response and the brand asset kit, nothing else.
# ===========================================================================


def test_the_renderer_imports_nothing_from_a_signing_or_receipt_path(report):
    src = pathlib.Path(report.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    # Only the standard library and weasyprint: nothing on a signing, receipt,
    # evidence-pack, digest, anchoring, chain or failsafe path can be reached.
    assert set(imported) <= {"__future__", "html", "json", "pathlib", "typing", "weasyprint"}, imported
    assert "scan.engine_response" in src  # it reads the engine's answer
