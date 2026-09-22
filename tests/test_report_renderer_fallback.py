"""The branded report can fail over to the plain one, but not in silence.

`render_scan_pdf_bytes` prefers the Mythos HTML/WeasyPrint renderer and falls
back to ReportLab when it raises. The fallback is deliberate and stays: a
plainer report beats a 500 on the download and email paths.

What was not deliberate is that the fallback said nothing. The only signal was
a traceback printed when DEBUG happened to be on -- which is exactly when nobody
is watching production. So a branded renderer broken by a missing native library
looked, from the outside, identical to one that was simply never needed:
customers received the plainer document and no record said which.

Not a hypothetical. `pentest.report_mythos` imports weasyprint at module scope,
so an environment where that wheel or its native libraries are absent takes this
path on *every* report, and used to take it without a word.

These tests inject the renderer module through `sys.modules` rather than
importing it, so they measure the fallback signal in an environment where
weasyprint is installed and in one where it is not.
"""

from __future__ import annotations

import logging
import sys
import types

import pytest

from pentest import utils

_MODULE = "pentest.report_mythos"


class _Scan:
    """Just enough scan for the log line; both renderers are stubbed here."""

    uuid = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def stub_fallback(monkeypatch):
    """Stand in for the ReportLab renderer so these tests measure the signal,
    not the PDF."""
    sentinel = b"%PDF-reportlab-fallback"
    monkeypatch.setattr(
        utils, "_render_scan_pdf_bytes_reportlab", lambda scan: sentinel
    )
    return sentinel


def _install_renderer(monkeypatch, render):
    module = types.ModuleType(_MODULE)
    module.render_scan_pdf_bytes_html = render
    monkeypatch.setitem(sys.modules, _MODULE, module)


def _install_failing_renderer(monkeypatch, exc):
    def _boom(scan, context=None):
        raise exc

    _install_renderer(monkeypatch, _boom)


def test_a_failing_html_renderer_is_reported(monkeypatch, caplog, stub_fallback):
    _install_failing_renderer(monkeypatch, RuntimeError("libpango missing"))

    with caplog.at_level(logging.WARNING, logger="pentest.utils"):
        out = utils.render_scan_pdf_bytes(_Scan())

    assert out == stub_fallback, "the fallback must still happen"

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings, "the fall back to the plainer report went unreported"
    assert _Scan.uuid in warnings[0].getMessage(), (
        "the record must say which scan got the plainer document"
    )


def test_a_missing_renderer_module_is_reported(monkeypatch, caplog, stub_fallback):
    """The live shape of this failure: the import itself raises, before any
    renderer function is reached."""
    monkeypatch.setitem(sys.modules, _MODULE, None)

    with caplog.at_level(logging.WARNING, logger="pentest.utils"):
        out = utils.render_scan_pdf_bytes(_Scan())

    assert out == stub_fallback
    assert [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_the_report_carries_the_cause(monkeypatch, caplog, stub_fallback):
    """A warning that does not carry the exception turns one silence into
    another: the operator learns that something failed and not what."""
    _install_failing_renderer(monkeypatch, RuntimeError("libpango missing"))

    with caplog.at_level(logging.WARNING, logger="pentest.utils"):
        utils.render_scan_pdf_bytes(_Scan())

    record = next(r for r in caplog.records if r.levelno >= logging.WARNING)
    assert record.exc_info is not None, "the original traceback was dropped"
    assert "libpango missing" in logging.Formatter().formatException(record.exc_info)


def test_a_working_html_renderer_is_quiet(monkeypatch, caplog, stub_fallback):
    """Without this, a logger that fired unconditionally would pass the tests
    above while telling an operator nothing at all."""
    expected = b"%PDF-mythos-html"
    _install_renderer(monkeypatch, lambda scan, context=None: expected)

    with caplog.at_level(logging.WARNING, logger="pentest.utils"):
        out = utils.render_scan_pdf_bytes(_Scan())

    assert out == expected
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
