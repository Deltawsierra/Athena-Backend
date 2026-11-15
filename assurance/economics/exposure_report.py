"""A deployment's economic-exposure report: a document a customer can be handed (the
owner's decision 12, 1 Nov 2026; ``docs/economics/spec-v1.md``, section 38).

Composed from what the read routes already serve, and only that: the scenario
versions, their reviews, and the report of one stored run (:func:`report.build_report`,
with its own ``integrity``). Rendered as HTML or PDF. It is READ-ONLY: it records,
recomputes, signs and verifies nothing, and asks no engine.

- **The selection rule** (the owner's choice of 22 Oct): the most recent APPROVED
  scenario version -- its latest review an approval that counts now
  (:func:`~assurance.economics.models.approval_standing`) -- with a completed exposure
  run whose stored rows verify. Its latest completed run is the one read; if that run's
  rows fail a check the version is passed over, never an older run of it shown. With
  none, the report says so and shows no figure. A draft figure is never shown.
- **Unmeasured is never green.** Every gap is named under "What is not measured", and
  a report with any gap reads ``AUDIT_INCOMPLETE`` (``mythos_core.status``).
- **Integrity in honest words.** The stored rows' ``integrity`` status, as the report
  states it; a receipt is "on record", and its signature is not re-verified here.
- **Every text is escaped**, in the HTML and in the PDF: a scenario's title is the
  customer's own text.

Nothing here is on a stop path: it is reached only from its route in
:mod:`.report_api`, which imports it inside the view.
"""

from __future__ import annotations

import html
import io

from mythos_core import status as core_status

from . import report
from .models import (
    SIMULATION_COMPLETED,
    FinancialScenario,
    RemediationOption,
    SimulationResult,
    approval_standing,
    input_authors,
    latest_review,
)

TITLE = "Economic exposure report"
SELECTION_RULE = (
    "the most recent approved scenario version with a completed run whose integrity checks verify; a draft or "
    "unverified figure is never shown"
)
NONE_SELECTED = (
    "No approved scenario version of this deployment has a completed run whose integrity checks verify: no "
    "exposure figure is shown."
)
#: What the report says where every item it covers is measured.
COMPLETE = "complete for the items this report covers; read it with its limitations"
LINE_LABELS = {
    "gross_cash": "Gross exposure (cash, before insurance)",
    "retained_cash": "Net exposure (cash retained after insurance)",
    "market_value": "Market value (never added to cash)",
}
FIGURE_LABELS = (
    ("expected_annual_loss", "Expected annual loss (EAL)"),
    ("p10", "P10"),
    ("p50", "P50"),
    ("p90", "P90"),
    ("severe_plausible", "Severe but plausible"),
)


def _approval(version: FinancialScenario) -> str | None:
    """Why ``version`` is not approved now, or ``None`` where its latest review is an
    approval that counts (the receipt gate's own rule, read whatever the gate's switch)."""
    return approval_standing(latest_review(version.pk), FinancialScenario.authors_of(version.pk),
                             input_authors(version.pk))


def _named(version: FinancialScenario) -> str:
    return f"scenario version “{version.title}” ({version.uuid})"


def select(deployment) -> tuple[tuple[FinancialScenario, dict] | None, list[str]]:
    """``((version, its run's report), passed_over)`` under the selection rule, or
    ``(None, passed_over)``: ``passed_over`` says why each newer version is not shown."""
    passed_over = []
    for version in FinancialScenario.objects.filter(deployment=deployment).order_by("-id"):
        why = _approval(version)
        if why is not None:
            passed_over.append(f"{_named(version)} is not approved: {why}")
            continue
        run = (SimulationResult.objects.exposure_runs()
               .filter(scenario=version, deployment=deployment, status=SIMULATION_COMPLETED).order_by("-id").first())
        if run is None:
            passed_over.append(f"{_named(version)} is approved, but no completed run is recorded for it")
            continue
        built = report.build_report(run)
        integrity = built["integrity"]
        if not (report.verifies(built) and integrity["verified"] is True and built["residual_of"] is None
                and built["status"] == SIMULATION_COMPLETED):
            passed_over.append(f"{_named(version)} is approved, but the stored rows of its latest completed run "
                               f"fail integrity checks: {', '.join(integrity['failed']) or 'its digest'}")
            continue
        return (version, built), passed_over
    return None, passed_over


def _lines(summary: dict, label: str, gaps: list[str]) -> list[tuple[str, str]]:
    """Each line's EAL, P10 to P90 and severe figure, and every one not measured named."""
    rows, code = [], summary.get("currency") or ""
    severe = summary.get("severe_percentile")
    for line, name in LINE_LABELS.items():
        block = (summary.get("lines") or {}).get(line) or {"not_reported": "not reported"}
        if "p50" not in block:
            gaps.append(f"{label}{name}: not measured: {block.get('not_reported')}")
            continue
        for key, figure in FIGURE_LABELS:
            figure = f"{figure} (P{severe})" if key == "severe_plausible" and severe else figure
            value = block.get(key)
            if value is None:
                gaps.append(f"{label}{name}, {figure}: not measured: "
                            f"{(block.get('not_reported') or {}).get(key, 'not reported')}")
            rows.append((f"{name}: {figure}", "not measured" if value is None else f"{code} {value}"))
    return rows


def _residual(version: FinancialScenario, gaps: list[str]) -> list[tuple[str, str]]:
    option = RemediationOption.objects.filter(scenario=version).first()
    run = None if option is None else SimulationResult.objects.residual_runs().filter(
        scenario=version, remediation=option).order_by("-id").first()
    if run is None:
        gaps.append("Residual exposure after a remediation option: not measured: "
                    + ("no remediation option is recorded" if option is None else "its residual run is not recorded"))
        return []
    built = report.build_report(run)
    if not (report.verifies(built) and built["integrity"]["verified"] is True
            and built["status"] == SIMULATION_COMPLETED):
        gaps.append("Residual exposure after a remediation option: not measured: its residual run was refused or "
                    f"its stored rows fail integrity checks ({', '.join(built['integrity']['failed']) or 'refused'})")
        return []
    rows = [("Remediation option", option.title),
            ("What this is", "modelled: the scenario as the option would leave it, not a measurement of a control "
                             "in place, and never added to a total"),
            ("Residual run", f"{run.uuid}, recorded {built['simulation']['recorded_at']}")]
    if built["banner"]:
        gaps.append(f"Residual exposure: {built['banner']}: {built['banner_reason']}")
    summary = {**built["summary"], "currency": built["currency"]["code"]}
    return rows + _lines(summary, "Residual: ", gaps)


def document(deployment) -> dict:
    """The report of ``deployment``, as plain text in sections; nothing escaped yet."""
    selected, passed_over = select(deployment)
    gaps: list[str] = list(passed_over)
    sections = []
    versions = []
    for version in FinancialScenario.objects.filter(deployment=deployment).order_by("id"):
        review = latest_review(version.pk)
        shown = selected is not None and selected[0].pk == version.pk
        versions.append((version.title, f"{version.uuid}; recorded {version.recorded_at.date().isoformat()}; latest "
                         f"review: {review.verdict if review else 'none (draft)'}"
                         + ("; shown in this report" if shown else "; not shown")))
    summary_rows = [("Deployment", f"{deployment.name} ({deployment.uuid})"), ("Selection rule", SELECTION_RULE)]
    if selected is None:
        gaps.insert(0, NONE_SELECTED)
        summary_rows.append(("Scenario shown", "none"))
    else:
        version, built = selected
        bridge = built["currency_bridge"]
        summary_rows += [
            ("Scenario shown", f"{version.title} ({version.uuid})"),
            ("As of", f"{bridge['valuation_date']} ({bridge['valuation_date_from']})"
             if bridge.get("valuation_date") else "not measured"),
            ("Validity grade", built["grade"] or "not graded"),
        ]
        if not bridge.get("valuation_date"):
            gaps.append(f"As-of date: not measured: {bridge.get('not_reported')}")
        if built["banner"]:
            gaps.append(f"{built['banner']}: {built['banner_reason']}")
        gaps.extend(f"{entry['kind']} {entry['id']}: {entry['reason']}" for entry in built["unknowns"])
        summary = {**built["summary"], "currency": built["currency"]["code"]}
        exposure = [("Basis", summary["basis"]), ("Currency", f"{built['currency']['code']} ({built['currency']['rounding']})")]
        sections.append(("Exposure", exposure + _lines(summary, "", gaps)))
        sections.append(("Residual exposure after controls", _residual(version, gaps)
                         or [("", "not measured: named under \u201cWhat is not measured\u201d")]))
        integrity, receipt = built["integrity"], built["receipt"]
        checks = f"{len(integrity['checks'])} checks of the stored rows ({', '.join(integrity['checks'])})"
        proof = [
            ("Run", f"{built['simulation']['uuid']}; recorded {built['simulation']['recorded_at']}; seed "
                    f"{built['simulation']['seed']}; {built['simulation']['draws']} draws"),
            ("Integrity", f"integrity checks verified: {checks}, none failed" if integrity["verified"]
             else f"integrity checks failed: {', '.join(integrity['failed'])}"),
        ]
        if receipt.get("receipt_id"):
            proof.append(("Receipt", f"receipt on record ({receipt['receipt_id']}, generated {receipt['generated_at']})"
                          "; its binding to the stored rows is among the integrity checks. Its signature is not "
                          "re-verified by this report: verify it against the engine's published economics-receipt "
                          "keys"))
        else:
            gaps.append(f"Receipt: not measured: {receipt.get('not_reported')}")
        sections.append(("Receipt and integrity", proof))
        assumptions = []
        for name, entry in sorted(built["parameters"].items()):
            if entry.get("withheld"):
                gaps.append(f"Assumption {name}: figures withheld: {entry['withheld']}")
            assumptions.append((name, f"low {entry.get('low')}, base {entry.get('base')}, high {entry.get('high')} "
                                f"{entry.get('currency') or entry.get('unit')}; source {entry.get('source_type')}; "
                                f"evidence {entry.get('evidence_ref') or 'none named'}; effective "
                                f"{entry.get('effective_date')}"))
        sections.append(("Assumptions and their sources", assumptions))
        sections.append(("Limitations", [("", text) for text in built["limitations"]]))
    sections.insert(0, ("Scenarios of this deployment", versions or [("", "no scenario version is recorded")]))
    status = core_status.AUDIT_INCOMPLETE if gaps else COMPLETE
    summary_rows.insert(1, ("Status", f"{status}: {len(gaps)} gaps named under “What is not measured”"
                            if gaps else status))
    sections.insert(0, ("Summary", summary_rows))
    sections.append(("What is not measured", [("", gap) for gap in gaps] or [("", "nothing this report covers")]))
    return {"title": f"{TITLE}: {deployment.name}", "status": status, "sections": sections}


# ------------------------------------------------------------------ rendering: every text escaped


def _e(text) -> str:
    return html.escape(str(text), quote=True)


_STYLE = ("body{font-family:sans-serif;max-width:60em;margin:2em auto;padding:0 1em;color:#111;background:#fff}"
          "th{text-align:left;vertical-align:top;padding-right:1em;font-weight:600}td{vertical-align:top}"
          "h2{border-bottom:1px solid #999;margin-top:1.5em}")


def render_html(served: dict) -> str:
    parts = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{_e(served['title'])}</title>"
             f"<style>{_STYLE}</style></head><body><h1>{_e(served['title'])}</h1>"]
    for heading, rows in served["sections"]:
        parts.append(f"<h2>{_e(heading)}</h2><table>")
        parts.extend(f"<tr><th>{_e(label)}</th><td>{_e(value)}</td></tr>" for label, value in rows)
        parts.append("</table>")
    parts.append("</body></html>")
    return "".join(parts)


def render_pdf(served: dict) -> bytes:
    """The same document as a PDF, deterministic for the same rows (``invariant``)."""
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate

    styles = getSampleStyleSheet()
    flow = [Paragraph(_e(served["title"]), styles["Title"])]
    for heading, rows in served["sections"]:
        flow.append(Paragraph(_e(heading), styles["Heading2"]))
        flow.extend(Paragraph(f"<b>{_e(label)}</b>: {_e(value)}" if label else _e(value), styles["BodyText"])
                    for label, value in rows)
    buffer = io.BytesIO()
    SimpleDocTemplate(buffer, invariant=1, pageCompression=0, title=served["title"]).build(flow)
    return buffer.getvalue()
