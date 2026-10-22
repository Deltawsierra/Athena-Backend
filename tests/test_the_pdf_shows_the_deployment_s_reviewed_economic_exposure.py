"""The customer PDF shows the scan's DEPLOYMENT current REVIEWED economic exposure
(Economic Exposure, PART 2) -- display-only, in BOTH editions, from one context key.

``report_mythos`` renders two editions (obsidian default, print). This section is
additive and display-only: it reads nothing but the ``economics_exposure`` context
``pentest.views`` assembles read-only (the figures, the scenario it belongs to and
when it was reviewed, and whether a Financial Exposure Receipt is signed and the
record's integrity verifies). It recomputes nothing, reads no scan field, and adds
no import -- the renderer stays import-clean. Absent context -> the section is
omitted, both editions, and the report renders exactly as before.

weasyprint is stubbed through ``sys.modules`` as
tests/test_the_report_shows_the_engine_s_coverage_retest_and_narrative.py does; the
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


#: A flat, display-ready exposure, exactly the shape pentest.views assembles: the
#: scenario it belongs to and its review date (the honest label), the already-computed
#: figures as the economics report exposes them, and the read-only receipt/integrity
#: status (signed & verified).
_EXPOSURE = {
    "title": "Customer PII breach via the sign-in form",
    "reviewed_at": "2026-10-20",
    "verified": True,
    "receipt_verified": True,
    "figures": [
        {"label": "Expected annual loss", "value": "USD 1250000.00"},
        {"label": "Annual loss P10–P90", "value": "USD 240000.00 – 5100000.00"},
        {"label": "Severe plausible loss", "value": "USD 9800000.00"},
    ],
}

_BUILDERS = [("_economics", "obsidian"), ("_p_economics", "print")]


def _scan(engine_response=None):
    return types.SimpleNamespace(engine_response=engine_response or {"results": []})


def _ctx(report, exposure, variant="obsidian"):
    context: dict = {"variant": variant}
    if exposure is not None:
        context["economics_exposure"] = exposure
    return report._extract(_scan(), context)


def _full_doc(report, exposure, variant="obsidian"):
    context: dict = {"variant": variant} if variant == "print" else {}
    if exposure is not None:
        context["economics_exposure"] = exposure
    pdf = report.render_scan_pdf_bytes_html(_scan(), context or None)
    assert pdf == b"%PDF-1.4 stub"
    return report._captured_doc["doc"]


# --- the context passes straight through _extract to the section builders ----


def test_extract_passes_the_economics_exposure_through(report):
    assert _ctx(report, _EXPOSURE)["economics_exposure"] == _EXPOSURE
    # Absent from context -> absent from the render ctx (the section then omits).
    assert _ctx(report, None)["economics_exposure"] is None


# --- the section shows the figures, the honest label and the receipt line ----


@pytest.mark.parametrize("builder,variant", _BUILDERS)
def test_the_section_shows_figures_the_honest_label_and_a_verified_receipt(report, builder, variant):
    page = getattr(report, builder)(_ctx(report, _EXPOSURE, variant))
    # Labelled honestly as the DEPLOYMENT's current exposure, naming the scenario
    # and when it was reviewed -- never as a per-scan recomputation.
    assert "Economic exposure" in page
    assert "Customer PII breach via the sign-in form" in page
    assert "reviewed 2026-10-20" in page
    # The already-computed figures, as the economics report exposes them.
    assert "USD 1250000.00" in page  # expected annual loss
    assert "240000.00" in page and "5100000.00" in page  # the P10-P90 band
    assert "USD 9800000.00" in page  # severe plausible
    # The receipt line, from the read-only integrity status (not a signature re-verify).
    assert "Financial Exposure Receipt" in page
    assert "signed &amp; verified" in page
    assert "not available" not in page


@pytest.mark.parametrize("builder,variant", _BUILDERS)
def test_an_unverified_receipt_reads_not_available(report, builder, variant):
    exposure = {**_EXPOSURE, "receipt_verified": False}
    page = getattr(report, builder)(_ctx(report, exposure, variant))
    assert "not available" in page
    assert "signed &amp; verified" not in page
    assert "USD 1250000.00" in page  # the figures still show


# --- default-safe: absent / empty exposure -> the section is omitted ----------


@pytest.mark.parametrize("builder,variant", _BUILDERS)
def test_absent_exposure_omits_the_section(report, builder, variant):
    assert getattr(report, builder)(_ctx(report, None, variant)) == ""


@pytest.mark.parametrize("builder,variant", _BUILDERS)
@pytest.mark.parametrize("exposure", [{"figures": []}, {"title": "x"}, {"figures": "nope"}, {}])
def test_an_exposure_with_no_figures_omits_the_section(report, builder, variant, exposure):
    assert getattr(report, builder)(_ctx(report, exposure, variant)) == ""


# --- the full render of BOTH editions includes it when present, omits otherwise


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_the_full_report_includes_the_section_when_present(report, variant):
    doc = _full_doc(report, _EXPOSURE, variant)
    assert "Economic exposure" in doc
    assert "Customer PII breach via the sign-in form" in doc
    assert "USD 1250000.00" in doc
    assert "signed &amp; verified" in doc


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_the_full_report_omits_the_section_when_absent(report, variant):
    doc = _full_doc(report, None, variant)
    assert doc  # still a full document
    assert "Economic exposure" not in doc
    assert "Financial Exposure Receipt" not in doc


# --- the displayed strings are escaped as text, never HTML --------------------


@pytest.mark.parametrize("builder,variant", _BUILDERS)
def test_the_exposure_strings_are_escaped(report, builder, variant):
    exposure = {
        "title": "<script>alert(1)</script>",
        "reviewed_at": "2026-10-20",
        "receipt_verified": True,
        "figures": [{"label": "Loss <b>", "value": "USD <i>9</i>"}],
    }
    page = getattr(report, builder)(_ctx(report, exposure, variant))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "<i>9</i>" not in page
    assert "&lt;i&gt;9&lt;/i&gt;" in page


# --- the renderer stays import-clean: this change added no import -------------


def test_the_renderer_imports_nothing_new(report):
    src = pathlib.Path(report.__file__).read_text(encoding="utf-8")
    imported: list[str] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert set(imported) <= {"__future__", "html", "json", "pathlib", "typing", "weasyprint"}, imported
