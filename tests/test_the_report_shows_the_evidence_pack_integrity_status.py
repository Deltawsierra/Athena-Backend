"""The customer PDF shows a compact Evidence-Pack Integrity status block -- the
tamper-evidence trust signal the dashboard shows (pack signed, chain verified,
anchored) -- in both editions, DISPLAY ONLY.

The renderer reads the status from context assembled read-only upstream
(``evidence_integrity``) or, near-fidelity like the coverage manifest, from an
engine-emitted pack summary on ``scan.engine_response`` (``evidence_pack`` /
``evidence_integrity``). It shows only the recorded status (and, for an unsigned
pack, the engine's own reason); it never reads a digest, signature, pack head or
any key material, never re-signs, never re-verifies, and never claims ``verified``
unless the recorded status says so.

Additive and default-safe: a scan carrying no usable status renders exactly as
before (the block omitted) and never crashes -- so the block is dormant until a
pack summary is emitted into a read-only channel, which is expected now. The
weasyprint stub mirrors tests/test_the_report_shows_the_engine_s_coverage_retest_and_narrative.py.
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
    mod._captured_doc = captured
    return mod


# --- Fixtures of what an integrity summary looks like ----------------------

#: A pack the platform signed, whose chain verified and which was anchored.
_PACK_OK = {"signed": True, "chain_verified": True, "anchored": True}

#: The honest opposite: unsigned (with the engine's reason), chain not verified,
#: not anchored -- what a scan recorded before a signer key is deployed.
_PACK_BAD = {"signed": False, "signed_reason": "signer key not yet deployed",
             "chain_verified": False, "anchored": False}

#: The dashboard's own field spellings (server/engine.ts EvidencePack).
_PACK_DASH = {"signed": True, "chainOk": True, "chainAnchored": False}

#: A summary that also carries key material the block must never emit.
_PACK_KEYS = {"signed": True, "chain_verified": True, "anchored": True,
              "pack_head": "ab" * 32, "signature": "ZZZSIGNATUREBYTESZZZ",
              "digest": "sha256:deadbeefcafe", "key_id": "KEYID-XYZ-9000"}

#: A reason carrying characters that must come back escaped, never as HTML.
_REASON_HTML = "<b>key</b> rotated & 50% done"


def _scan(engine_response):
    return types.SimpleNamespace(engine_response=engine_response)


def _ctx(report, engine_response=None, variant="obsidian", context=None):
    base: dict = {"variant": variant}
    if context:
        base.update(context)
    return report._extract(_scan(engine_response if engine_response is not None else {"results": []}), base)


def _full_doc(report, engine_response, variant="obsidian"):
    context = {"variant": "print"} if variant == "print" else None
    pdf = report.render_scan_pdf_bytes_html(_scan(engine_response), context)
    assert pdf == b"%PDF-1.4 stub"
    return report._captured_doc["doc"]


# ===========================================================================
# Present: the compact block shows the real status in both editions.
# ===========================================================================


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_a_signed_verified_anchored_pack_shows_the_integrity_block(report, variant):
    block = report._integrity_block(_ctx(report, context={"evidence_integrity": _PACK_OK}, variant=variant))
    assert "Evidence Pack Integrity" in block
    assert "Pack signed" in block
    assert "Chain verified" in block
    assert "Anchored" in block


@pytest.mark.parametrize("builder,variant", [("_compliance", "obsidian"), ("_p_evidence", "print")])
def test_the_integrity_block_is_injected_into_both_editions_sections(report, builder, variant):
    page = getattr(report, builder)(_ctx(report, {"results": [], "evidence_pack": _PACK_OK}, variant))
    assert "Evidence Pack Integrity" in page
    assert "Pack signed" in page and "Chain verified" in page and "Anchored" in page


def test_an_unsigned_unverified_pack_shows_the_honest_status_never_verified(report):
    block = report._integrity_block(_ctx(report, context={"evidence_integrity": _PACK_BAD}))
    assert "Pack unsigned" in block
    assert "signer key not yet deployed" in block  # the engine's own reason
    assert "Chain not verified" in block
    assert "Not anchored" in block
    # The positive claims must never appear for a pack that is not signed/verified.
    assert "Pack signed" not in block
    assert "Chain verified" not in block  # only "Chain not verified" is present


def test_the_dashboard_field_spellings_are_understood(report):
    block = report._integrity_block(_ctx(report, context={"evidence_integrity": _PACK_DASH}))
    assert "Pack signed" in block and "Chain verified" in block
    assert "Not anchored" in block


def test_a_partial_summary_shows_only_what_was_recorded(report):
    block = report._integrity_block(_ctx(report, context={"evidence_integrity": {"signed": True}}))
    assert "Pack signed" in block
    assert "Chain status not recorded" in block
    assert "Anchoring not recorded" in block


# ===========================================================================
# Default-safe: no / unusable status -> the block is omitted, never a crash.
# ===========================================================================


@pytest.mark.parametrize("builder,variant", [("_compliance", "obsidian"), ("_p_evidence", "print")])
def test_a_scan_without_a_pack_status_omits_the_block(report, builder, variant):
    page = getattr(report, builder)(_ctx(report, {"results": []}, variant))
    assert "Evidence Pack Integrity" not in page  # omitted, not fabricated


@pytest.mark.parametrize("bad", ["", [], 0, None, {}, {"foo": "bar"}, {"pack_head": "ab" * 32}])
def test_an_unusable_integrity_value_omits_the_block(report, bad):
    # No recognised boolean status (pack_head alone is key material, not a status).
    assert report._integrity_block(_ctx(report, context={"evidence_integrity": bad})) == ""


# ===========================================================================
# DISPLAY ONLY: never key material, reason escaped as text.
# ===========================================================================


def test_the_block_never_emits_key_material(report):
    block = report._integrity_block(_ctx(report, context={"evidence_integrity": _PACK_KEYS}))
    assert "Pack signed" in block  # it still shows the status
    assert "ab" * 32 not in block  # but never the pack head
    assert "ZZZSIGNATUREBYTESZZZ" not in block
    assert "sha256:deadbeefcafe" not in block
    assert "KEYID-XYZ-9000" not in block


def test_the_unsigned_reason_is_escaped_as_text_never_html(report):
    pack = dict(_PACK_BAD, signed_reason=_REASON_HTML)
    block = report._integrity_block(_ctx(report, context={"evidence_integrity": pack}))
    assert "<b>key</b>" not in block
    assert "&lt;b&gt;key&lt;/b&gt;" in block


# ===========================================================================
# Both data channels: engine_response summary, and read-only context.
# ===========================================================================


def test_the_engine_response_pack_summary_channel_lights_up(report):
    page = report._compliance(_ctx(report, {"results": [], "evidence_pack": _PACK_OK}))
    assert "Evidence Pack Integrity" in page


def test_the_read_only_context_channel_lights_up(report):
    page = report._compliance(_ctx(report, {"results": []}, context={"evidence_integrity": _PACK_OK}))
    assert "Evidence Pack Integrity" in page


# ===========================================================================
# Full render of both editions, with the status and without it.
# ===========================================================================


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_the_full_report_shows_the_integrity_block_when_present(report, variant):
    doc = _full_doc(report, {"results": [{"type": "xss", "severity": "low"}], "evidence_pack": _PACK_OK}, variant)
    assert "Evidence Pack Integrity" in doc
    assert "Pack signed" in doc


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_the_full_report_renders_without_a_pack_status(report, variant):
    doc = _full_doc(report, {"results": [{"type": "xss", "severity": "low"}]}, variant)
    assert doc  # still a document
    assert "Evidence Pack Integrity" not in doc


@pytest.mark.parametrize("variant", ["obsidian", "print"])
def test_an_empty_engine_response_still_renders(report, variant):
    assert _full_doc(report, {}, variant)


# ===========================================================================
# No signing/receipt path is reached: the renderer stays import-clean (the
# #185 guard), and it reads the status from the engine's answer / context.
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
    assert set(imported) <= {"__future__", "html", "json", "pathlib", "typing", "weasyprint"}, imported
    # The status is read off the engine's answer / context, not fetched or re-signed.
    assert "scan.engine_response" in src
    assert "evidence_integrity" in src
