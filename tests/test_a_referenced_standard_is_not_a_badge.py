"""The PDF's standards panel claims no conformance it did not measure.

It used to list OWASP Top 10, OWASP ASVS 4.0.3 and CWE as "Mapped" beside a green
check, which reads as a compliance badge; the report cross-references findings to
those standards and measures conformance to none of them. Such a standard now reads
"Referenced", with no check, under a note that says so. CVSS (applied to every
finding) and the header review (performed) keep their check.

weasyprint is stubbed through sys.modules, as tests/test_report_renderer_fallback.py
does: only the page's HTML is read, nothing is rendered.
"""

from __future__ import annotations

import importlib
import sys
import types

import pytest


@pytest.fixture
def report(monkeypatch):
    stub = types.ModuleType("weasyprint")
    stub.HTML = object
    monkeypatch.setitem(sys.modules, "weasyprint", stub)
    monkeypatch.delitem(sys.modules, "pentest.report_mythos", raising=False)
    return importlib.import_module("pentest.report_mythos")


def _page(report) -> str:
    return report._p_compliance({"highest": "medium", "client": "Acme"})


def _row(page: str, name: str) -> str:
    start = page.index(f'<td class="std-name">{name}</td>')
    return page[start : page.index("</tr>", start)]


@pytest.mark.parametrize("name", ["OWASP Top 10 (2021)", "OWASP ASVS 4.0.3", "CWE"])
def test_a_referenced_standard_carries_no_check(report, name):
    row = _row(_page(report), name)
    assert "Referenced" in row
    assert report.CK_GREEN not in row


@pytest.mark.parametrize("name", ["CVSS v3.1", "Security Headers"])
def test_what_the_assessment_did_keeps_its_check(report, name):
    assert report.CK_GREEN in _row(_page(report), name)


def test_the_panel_says_it_claims_no_conformance(report):
    page = _page(report)
    assert report.REFERENCED_NOTE in page
    assert "Mapped" not in page
    assert "Standards Alignment" not in page
