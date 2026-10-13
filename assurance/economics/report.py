"""The report JSON of a stored simulation result, and a scenario's own document
(MVP step 6; ``docs/economics/spec-v1.md``, section 27).

:func:`build_report` composes ONE result's report from what is stored, and only
that: the scenario version's rows, its build, the stored result, its Validity Card
and sensitivity analysis (step 8), its chart series (:mod:`.charts_service`) and its
receipt, where recorded. It runs no simulation, reads no clock and asks no engine.

- **Deterministic.** The same stored rows give the same bytes: canonical JSON (sorted
  keys, no whitespace, ASCII, no float, :func:`canonical_bytes`), every list in an
  order the rows fix, and no wall-clock field but the stored times (when the run
  started, finished and was recorded, when the card was issued, when the receipt
  was generated). A key order the stored JSON happens to have changes nothing.
- **Its own digest.** ``digest`` is ``sha256:`` and the SHA-256 of the canonical bytes
  of the report without it (:func:`digest_of`, :func:`verifies`).
- **Money at the currency's minor unit.** Every amount of loss the report states (a
  component's and an event's low, base and high, the summary's figures and bands, the
  chart series' losses and edges, the tornado's outcomes) is the stored amount
  rounded half-even to the minor unit (``Money.display_amount``): 0 places for JPY, 3
  for KWD. A parameter's own figures are shown as recorded: a cost per unit may lie
  below the minor unit (USD 0.375 a record).
- **A refusal is served as the refusal**, never as figures: a refused run has no
  summary, no series and no tornado, and the report says why.
- **Every stored row is checked before it is served** (review round 1, MEDIUM-1):
  the result's inputs and record give their digests, the card its digest, its grade
  column the grade its document states, and its reproduction the result's identity,
  the analysis the digest the card signs, and the series its digest and the result's
  identity (:func:`stored_row_failures`). A result whose rows fail a check is served
  as a refusal (``stored_row_unverified``, naming the checks), and a card that fails
  one counts as no card. The grade is the card DOCUMENT's, never the column's.
- **Unknown is not for capital decisions** (the owner-adopted default): a result
  graded Unknown -- or refused, or not graded at all, or unverified -- still shows
  whatever figures it may, with ``banner`` :data:`UNKNOWN_BANNER` and
  ``excluded_from_totals: true``. Nothing may sum such a result into a total, now or
  later: :func:`may_be_totalled` is the one test a total applies, and it fails
  closed.
- **One rule, two routes.** :func:`banner_reason` is the rule, and :func:`standing` is
  the scenario version's latest stored result under it: the report applies the first
  to its result, and the step-5 events route (``scenario_api``) serves the second
  beside its deterministic figures, which are not a result and stay. The deployment's
  scenario list (:func:`scenario_entry`, section 30) applies it to each version's
  latest exposure run too.
- **The valuation date and the currency bridge** (``currency_bridge``, schema v2,
  section 30): the run's valuation date, read from the stored rows the receipt
  reads it from, and the normalization record of each figure the run converted:
  each figure its build normalized (section 36), as the run's stored inputs hold it,
  so the input digest the integrity checks hold covers it (:data:`CONVERTED`), a
  source whose licence does not allow redistributing its raw data shown by its
  provenance only; none for a run whose build normalized nothing
  (:data:`NO_CONVERSION`). Nothing is converted or recomputed here.

Nothing here is on a stop path. This module imports nothing probabilistic: the step-8
and builder modules it reads are imported when a report is built, never at load.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from decimal import Decimal

from assurance.models import Deployment

from . import run_normalization
from .engine import currency as _currency
from .engine import loss as engine_loss
from .engine.formulas import MARKET_VALUE
from .engine.money import Money
from .engine.parameters import MONEY_UNITS, POINTS
from .models import (
    CARD_GRADES,
    SIMULATION_COMPLETED,
    CausalEffect,
    CustomerParameterSet,
    EffectFinding,
    FinancialExposureReceipt,
    FinancialParameter,
    FinancialScenario,
    FinancialValidityCard,
    LossComponent,
    LossEvent,
    RemediationOption,
    ScenarioBuild,
    SimulationCharts,
    SimulationResult,
    canonical_digest,
    card_digest,
)

#: The report's schema. v2 is v1 and ``currency_bridge``: the run's valuation date and
#: the normalization record of each figure the run converted (none: a run converts
#: nothing, :data:`NO_CONVERSION`). v1 stays readable: :func:`may_be_totalled` reads a
#: v1 report exactly as before.
REPORT_SCHEMA = "mythos.economics.report/v2"
REPORT_SCHEMA_V1 = "mythos.economics.report/v1"
#: Every report schema ever served, oldest first.
REPORT_SCHEMAS: tuple[str, ...] = (REPORT_SCHEMA_V1, REPORT_SCHEMA)
#: Where a run's valuation date is read from: its scenario build's as-of date (the date
#: the receipt signs as its valuation date, section 26.5), or, for a version with no
#: build, the latest as-of date of the components its stored inputs hold (the
#: receipt's rule too).
VALUATION_FROM_BUILD = "the scenario build's as-of date"
VALUATION_FROM_INPUTS = "the latest as-of date of the run's components, as its stored inputs hold them"
#: What the currency bridge says of a run's conversions. Nothing is converted inside a
#: run (an event, a policy or a component's inputs in another currency are refused,
#: ``currency_mismatch``), and no normalization record is stored for any figure, so
#: none is served; none is ever computed here.
NO_CONVERSION = (
    "every figure is stated in the reporting currency as recorded: a run converts nothing (an event, a policy or a "
    "component's inputs in another currency are refused, currency_mismatch), so no figure has a normalization "
    "record to serve, and none is computed here"
)
#: What the currency bridge says of a run whose build normalized figures (section 36).
CONVERTED = (
    "each figure the scenario build normalized into the reporting currency at the valuation date (section 36): the "
    "parameter-set figure as stated, the figure the run read in its place, and each point's normalization record "
    "with its chain, downgrades, conflicts and fallbacks, as the run's stored inputs hold them, so the input digest "
    "covers them; a source whose licence does not allow redistributing its raw data is shown by its provenance only, "
    "and the figures derived from it stand. Nothing is converted or recomputed here"
)
#: The scenario document's schema.
SCENARIO_SCHEMA = "mythos.economics.scenario/v1"
#: What a result graded Unknown, refused or not graded shows (the owner-adopted default).
UNKNOWN_BANNER = "Unknown: not for capital decisions"
#: The reason a scenario version with no stored result is served with the banner (the
#: step-5 events route; a report is of a stored result, so it never says this).
NO_RESULT = "no simulation result is recorded for this scenario version: it is not graded"
#: The grade that is not for capital decisions.
UNKNOWN = "Unknown"
#: The grades a total may sum (an allow-list: anything else is refused).
GRADES_FOR_TOTALS = frozenset({"A", "B", "C", "D"})
#: The reason a result whose stored rows fail a check is served as a refusal.
STORED_ROW_UNVERIFIED = "stored_row_unverified"
#: The checks :func:`stored_row_failures` runs, in order: the result's (its inputs
#: and its record), the card's (its digest, its grade column against its document,
#: its reproduction against the result, its analysis against the digest it signs),
#: and the series' (its digest, its identity against the result).
RESULT_CHECKS = ("input_digest", "result_digest")
CARD_CHECKS = ("card_digest", "card_grade", "card_result", "sensitivity_digest")
CHARTS_CHECKS = ("charts_digest", "charts_result")
INTEGRITY_CHECKS = RESULT_CHECKS + CARD_CHECKS + CHARTS_CHECKS
#: A line's figures, as the report names them (the run's record names the expected
#: annual loss ``expected_annual_exposure``).
FIGURES = ("p10", "p50", "p90", "mean", "expected_annual_loss", "severe_plausible")
#: The scenario's lines, in this order.
LINES = ("gross_cash", "retained_cash", "market_value")
#: The rounding money is shown with (section 11.3).
ROUNDING = "ROUND_HALF_EVEN, to the currency's minor unit"

#: What the report is not, stated in every report.
LIMITATIONS = (
    "estimates of loss with their uncertainty, from the stated inputs and the rules recorded with the run; not a "
    "prediction, a valuation or advice, and not calibrated against realised losses (no calibration set exists)",
    "one reporting currency: nothing is converted inside a run, and currency uncertainty is not in the figures",
    "no dependency between parameters beyond what a simulated year shares: no copula, no shared-cause event",
    "one frequency per scenario; each occurrence realises every event once",
    "insurance applied per event occurrence, its limit included; no yearly aggregate limit",
    "the sensitivity tornado swings one parameter at a time; interactions are not shown",
    "a parameter's figures are as the customer, an expert, a benchmark or an observation states them; the evidence "
    "is named, not proven correct",
    "a result graded Unknown, refused, or not graded is not for capital decisions and is excluded from every total",
)


# ------------------------------------------------------------------ bytes


def canonical_bytes(document: Mapping) -> bytes:
    """The report's canonical JSON: sorted keys, no whitespace, ASCII, no float."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )


def digest_of(report: Mapping) -> str:
    """``sha256:`` and the SHA-256 of the canonical bytes of ``report`` without its
    ``digest``."""
    body = {key: value for key, value in report.items() if key != "digest"}
    return "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def verifies(report: Mapping) -> bool:
    """Whether ``report`` carries the digest of its own canonical bytes."""
    return report.get("digest") == digest_of(report)


def stands(report: Mapping) -> bool:
    """Whether ``report`` is a sound account of its run: it carries the digest of its
    own bytes, of a completed result whose stored rows verified, graded A to D (an
    allow-list). Says nothing of whether the run is exposure: :func:`may_be_totalled`
    does. The ROI document reads a residual run's report through this."""
    try:
        genuine = verifies(report)
    except (TypeError, ValueError, AttributeError):
        return False
    return (
        genuine
        and report.get("status") == SIMULATION_COMPLETED
        and report.get("grade") in GRADES_FOR_TOTALS
        and (report.get("integrity") or {}).get("verified") is True
    )


def may_be_totalled(report: Mapping) -> bool:
    """Whether a total may sum ``report``'s figures. It fails closed (review round 1,
    LOW-4): only a report of a schema this module serves or served
    (:data:`REPORT_SCHEMAS`, v1 and v2: an ROI document or any other is refused) that
    carries the digest of its own bytes, of a completed
    result whose stored rows verified, not excluded from totals, graded A to D (an
    allow-list), and of a scenario's OWN run: ``residual_of`` present and null (a
    residual run under a remediation option is never exposure, section 28; a report
    without the key is refused). A forged, edited or stale report is refused. A total
    of several reports applies this to each, and leaves out every one it refuses (the
    owner-adopted default)."""
    if not isinstance(report, Mapping) or report.get("schema") not in REPORT_SCHEMAS:
        return False
    if "residual_of" not in report or report["residual_of"] is not None:
        return False
    return stands(report) and report.get("excluded_from_totals") is False


# ------------------------------------------------------------------ the stored rows


def _digest(function, document) -> str | None:
    """``function(document)``, or ``None`` where the stored value cannot be digested."""
    try:
        return function(document)
    except (TypeError, ValueError):
        return None


def _result_failures(result: SimulationResult) -> list[str]:
    failed = []
    if _digest(canonical_digest, result.inputs) != result.input_digest:
        failed.append("input_digest")
    if result.status == SIMULATION_COMPLETED:
        if not isinstance(result.record, dict) or _digest(canonical_digest, result.record) != result.result_digest:
            failed.append("result_digest")
    elif result.record is not None or result.result_digest:
        failed.append("result_digest")
    return failed


def _card_failures(card: FinancialValidityCard | None, result: SimulationResult) -> list[str]:
    if card is None:
        return []
    failed = []
    document = card.card if isinstance(card.card, dict) else {}
    if _digest(card_digest, card.card) != card.card_digest:
        failed.append("card_digest")
    grade = document.get("confidence_grade")
    if grade != card.confidence_grade or grade not in CARD_GRADES:
        failed.append("card_grade")
    reproduction = (document.get("fields") or {}).get("reproduction") or {}
    held = (reproduction.get("seed"), reproduction.get("draws"), reproduction.get("input_digest"),
            reproduction.get("result_digest"))
    identity = (card.simulation_id, card.scenario_id, card.deployment_id)
    if identity != (result.pk, result.scenario_id, result.deployment_id) or held != (
        result.seed, result.draws, result.input_digest, result.result_digest or None
    ):
        failed.append("card_result")
    analysis = None if card.sensitivity is None else _digest(canonical_digest, card.sensitivity)
    if analysis != reproduction.get("sensitivity_digest") or (card.sensitivity_digest or None) != analysis:
        failed.append("sensitivity_digest")
    return failed


def _charts_failures(row: SimulationCharts | None, result: SimulationResult, scenario: FinancialScenario
                     ) -> list[str]:
    if row is None:
        return []
    failed = []
    charts = row.charts if isinstance(row.charts, dict) else {}
    if _digest(canonical_digest, row.charts) != row.charts_digest or charts.get("schema") != row.schema:
        failed.append("charts_digest")
    record = result.record if isinstance(result.record, dict) else {}
    named = (charts.get("scenario_id"), charts.get("seed"), charts.get("draws"), charts.get("input_digest"),
             charts.get("outcomes_sha256"))
    identity = (row.simulation_id, row.scenario_id, row.deployment_id)
    if (
        identity != (result.pk, result.scenario_id, result.deployment_id)
        or result.status != SIMULATION_COMPLETED
        or named != (str(scenario.uuid), result.seed, result.draws, result.input_digest, record.get("outcomes_sha256"))
    ):
        failed.append("charts_result")
    return failed


def stored_row_failures(
    result: SimulationResult,
    card: FinancialValidityCard | None,
    charts: SimulationCharts | None,
    scenario: FinancialScenario,
) -> list[str]:
    """The checks of :data:`INTEGRITY_CHECKS` that the stored rows of ``result`` fail,
    in order (none: every row is as recorded). Plain hashing: no engine, no numpy."""
    return _result_failures(result) + _card_failures(card, result) + _charts_failures(charts, result, scenario)


def verified_grade(card: FinancialValidityCard | None, result: SimulationResult) -> str | None:
    """The grade of ``card``, from its DOCUMENT, where the card and ``result`` verify
    (:func:`stored_row_failures`); ``None`` otherwise: a card that fails a check counts
    as no card."""
    if card is None or _result_failures(result) or _card_failures(card, result):
        return None
    return card.card["confidence_grade"]


def banner_reason(result: SimulationResult | None, grade: str | None, failed: list[str]) -> str | None:
    """Why ``result`` is not for capital decisions, or ``None`` where it may be totalled:
    a completed result whose stored rows verified (``failed`` is empty) and a ``grade``
    on the allow-list :data:`GRADES_FOR_TOTALS`. ``None`` for the result is a scenario
    version with none stored. It fails closed: a grade the list does not name is a
    reason. A reason is the one test of the banner (:data:`UNKNOWN_BANNER`) and of
    ``excluded_from_totals``, in the report and on the step-5 events route."""
    if result is None:
        return NO_RESULT
    if failed:
        return _unverified(failed)
    if result.status != SIMULATION_COMPLETED:
        return f"the run was refused ({result.refusal_code}): it has no figures"
    if grade is None:
        return "no Validity Card is recorded for this result: it is not graded"
    if grade == UNKNOWN:
        return "graded Unknown: Mythos cannot responsibly quantify this scenario"
    if grade not in GRADES_FOR_TOTALS:
        return f"graded {grade}: not a grade a total may sum"
    return None


def standing(scenario: FinancialScenario) -> dict:
    """The banner rule applied to ``scenario``'s latest stored result, by record order
    (the result ``results/`` serves without ``?simulation=``): the ``grade`` (the card
    DOCUMENT's, only where every stored row verified, else ``None``), the ``banner``,
    ``excluded_from_totals`` and ``banner_reason``. Every row is checked as the report
    checks it (:func:`stored_row_failures`, the series' too), and a scenario version
    with no result is not graded. Reads rows, hashes them and runs nothing else."""
    return _standing_of(scenario, latest_exposure_run(scenario))


def latest_exposure_run(scenario: FinancialScenario) -> SimulationResult | None:
    """``scenario``'s latest stored run, by record order, of its OWN runs, as
    ``results/`` serves them without ``?simulation=``: a residual run under a
    remediation option (section 28) is never the scenario's exposure."""
    return SimulationResult.objects.exposure_runs().filter(
        scenario=scenario, deployment_id=scenario.deployment_id
    ).order_by("-id").first()


def _standing_of(scenario: FinancialScenario, result: SimulationResult | None) -> dict:
    """The banner rule applied to ``result``, ``scenario``'s latest exposure run (see
    :func:`standing`)."""
    card = charts = None
    failed: list[str] = []
    if result is not None:
        card = FinancialValidityCard.objects.filter(simulation=result).first()
        charts = SimulationCharts.objects.filter(simulation=result).first()
        failed = stored_row_failures(result, card, charts, scenario)
    grade = None if result is None or failed else verified_grade(card, result)
    reason = banner_reason(result, grade, failed)
    return {
        "grade": grade,
        "banner": None if reason is None else UNKNOWN_BANNER,
        "excluded_from_totals": reason is not None,
        "banner_reason": reason,
    }


# ------------------------------------------------------------------ money


class _Shown:
    """Amounts of one currency, shown at its minor unit."""

    def __init__(self, code: str):
        self.code = code
        self.minor_unit = _currency.minor_units(code)

    def __call__(self, text) -> str | None:
        if text is None:
            return None
        amount = text.amount if isinstance(text, Money) else Decimal(text)
        return format(Money(amount, self.code).display_amount(), "f")

    def band(self, band) -> list | None:
        return None if band is None else [self(band[0]), self(band[1])]


# ------------------------------------------------------------------ parts


def _review(scenario: FinancialScenario) -> dict:
    from .builder import review_status

    return review_status(scenario)


def _scenario_part(scenario: FinancialScenario, deployment_uuid: str) -> dict:
    supersedes = None
    if scenario.supersedes_id:
        supersedes = str(FinancialScenario.objects.get(pk=scenario.supersedes_id).uuid)
    return {
        "uuid": str(scenario.uuid),
        "title": scenario.title,
        "deployment": deployment_uuid,
        "author": scenario.author_username or None,
        "recorded_at": scenario.recorded_at.isoformat(),
        "supersedes": supersedes,
        "review": _review(scenario),
    }


def _build_part(build: ScenarioBuild | None) -> dict | None:
    if build is None:
        return None
    return {
        "digest": build.build_digest,
        "builder": build.builder_version,
        "grouping": build.grouping_version,
        "pack": build.pack,
        "currency": build.currency,
        "as_of": build.as_of.isoformat(),
        "parameter_set": (build.inputs or {}).get("parameter_set"),
    }


def _policy(build: ScenarioBuild | None):
    # The version's policy, each term the build normalized read as its normalized figure.
    return run_normalization.policy_of(build)


def _loss_events(scenario: FinancialScenario, build: ScenarioBuild | None, shown: _Shown, *, figures: bool
                 ) -> list[dict]:
    """Each loss event's components and totals at low, base and high, step 4's
    Decimal figures shown at the minor unit, with the parameter each input reads.
    Without ``figures`` (a refused run) every amount is null: a refusal is served
    as the refusal, never as figures."""
    policy = _policy(build)
    events = []
    for row in LossEvent.objects.filter(scenario=scenario).order_by("event_key", "id"):
        event = row.as_engine()
        assessment = engine_loss.assess(event, policy)
        components = []
        # In the report, by component key (review round 1): the order the rows were
        # inserted in, which step 7b's inputs keep, never changes a report.
        for component in sorted(event.components, key=lambda c: c.component_id):
            known = figures and component.status == "estimated"
            components.append(
                {
                    "component_id": component.component_id,
                    "family": component.family,
                    "cash": component.family != MARKET_VALUE,
                    "formula": [component.formula.formula_id, component.formula.version],
                    "status": component.status,
                    **{point.value: shown(component.at(point)) if known else None for point in POINTS},
                    "unknown_reason": component.unknown_reason,
                    "missing": list(component.missing),
                    "reads": {cited.input.name: cited.parameter.name for cited in component.inputs},
                }
            )

        def total(line: engine_loss.Total) -> dict:
            return {
                **{point.value: shown(line.at(point)) if figures else None for point in POINTS},
                "complete": line.complete,
                "reads_as": "the loss" if line.complete else "at least: the known components only",
            }

        events.append(
            {
                "event_key": row.event_key,
                "currency": row.currency,
                "effect": row.effect or None,
                "business_process": row.business_process,
                "trigger": row.trigger,
                "components": components,
                "gross_cash": total(assessment.gross.total),
                "retained_cash": None if assessment.insured is None else total(assessment.insured.retained),
                "market_value": None
                if not event.market_value_components
                else {**total(assessment.market_value), "never_added_to_cash": True},
            }
        )
    return events


def _parameters(inputs: Mapping) -> dict:
    """Every parameter the run read, as its canonical inputs hold it, with what reads
    it (``read_by``): a component's input, a term of the policy, the frequency, or
    the derived value it was taken across into."""
    read_by: dict[str, list[str]] = {}
    for event in inputs.get("events", []):
        for component in event.get("components", []):
            for name, parameter in sorted(component.get("reads", {}).items()):
                read_by.setdefault(parameter, []).append(f"{event['event_key']}/{component['component_id']}.{name}")
    policy = inputs.get("policy") or {}
    for role, parameter in sorted((policy.get("terms") or {}).items()):
        read_by.setdefault(parameter, []).append(f"policy.{role}")
    if inputs.get("frequency"):
        read_by.setdefault(inputs["frequency"], []).append("frequency")
    for derived, contributors in sorted((inputs.get("derived") or {}).items()):
        for contributor in contributors:
            read_by.setdefault(contributor, []).append(f"derived:{derived}")
    return {
        name: {**parameter, "read_by": sorted(read_by.get(name, []))}
        for name, parameter in sorted(inputs.get("parameters", {}).items())
    }


def _block(block: Mapping | None, *, shown: _Shown, annual: bool, no_annual: str, missing: str) -> dict:
    """One line's summary, its money at the minor unit, and why each figure that is
    not reported is not."""
    if block is None:
        return {"not_reported": missing}
    figures = {key: block.get(key) for key in ("p10", "p50", "p90", "mean", "severe_plausible")}
    figures["expected_annual_loss"] = block.get("expected_annual_exposure")
    not_reported: dict[str, str] = {}
    mean_undefined = block.get("mean_undefined") or []
    error_undefined = block.get("standard_error_undefined") or []
    if figures["mean"] is None:
        not_reported["mean"] = (
            f"the mean does not exist: {', '.join(mean_undefined)} has an infinite mean; the percentiles are given"
        )
    if figures["expected_annual_loss"] is None:
        not_reported["expected_annual_loss"] = no_annual if not annual else not_reported.get("mean", "no mean")
    if block.get("standard_error_of_mean") is None:
        not_reported["standard_error_of_mean"] = (
            f"no standard error: {', '.join(error_undefined)} has an infinite variance, so a band from the sample "
            "would not cover at its level" if error_undefined else not_reported.get("mean", "no mean")
        )
    bands = {key: shown.band(band) for key, band in sorted((block.get("bands") or {}).items())}
    for key, band in bands.items():
        if band is None:
            not_reported[f"bands.{key}"] = not_reported.get("standard_error_of_mean", "no band")
    return {
        **{key: shown(value) for key, value in figures.items()},
        "standard_error_of_mean": shown(block.get("standard_error_of_mean")),
        "bands": bands,
        "not_reported": not_reported,
    }


def _summary(result: SimulationResult, shown: _Shown) -> dict:
    record = result.record
    scenario = record["scenario"]
    basis = record["basis"]
    statement = record["occurrences"]["statement"]
    missing = {
        "gross_cash": "no gross cash line",
        "retained_cash": "no insurance policy: the parameter-set version states no deductible and limit",
        "market_value": "no market-value component is known",
    }
    annual = basis == "annual_loss"
    lines = {
        line: _block(scenario.get(line), shown=shown, annual=annual, no_annual=f"no frequency: {statement}",
                     missing=missing[line])
        for line in LINES
    }
    per_occurrence = None
    if annual:
        held = scenario.get("per_occurrence")
        per_occurrence = (
            {"not_reported": "too few occurrences across the run's years to summarise one (step 7a's minimum draws)"}
            if held is None
            else {
                line: _block(held.get(line), shown=shown, annual=False,
                             no_annual="a figure of one occurrence: the expected annual loss is the annual line's",
                             missing=missing[line])
                for line in ("gross_cash", "retained_cash")
            }
        )
    return {
        "basis": basis,
        "statement": statement,
        "headline": scenario.get("headline"),
        "evaluated_by": scenario.get("evaluated_by"),
        "severe_percentile": record.get("severe_percentile"),
        "confidence_level": record.get("confidence_level"),
        "complete": scenario.get("complete"),
        "unknown_components": list(scenario.get("unknown_components") or []),
        "aggregate_limit_exceeded_share": scenario.get("aggregate_limit_exceeded_share"),
        "lines": lines,
        "per_occurrence": per_occurrence,
    }


def _charts(row: SimulationCharts | None, result: SimulationResult, shown: _Shown, withheld: str | None = None
            ) -> dict:
    if withheld is not None:
        return {"not_reported": withheld}
    if row is None:
        reason = (
            "a refused run has no figures to chart"
            if result.status != SIMULATION_COMPLETED
            else "no chart series is recorded for this result: simulating it again records them"
        )
        return {"not_reported": reason}
    charts = row.charts
    lines = {}
    for line in LINES:
        series = (charts.get("lines") or {}).get(line)
        if series is None:
            lines[line] = None
            continue
        histogram = series["histogram"]
        lines[line] = {
            "exceedance": [
                {**point, "loss": shown(point.get("loss"))} for point in series["exceedance"]
            ],
            "histogram": {
                "width": shown(histogram["width"]),
                "bins": [
                    {"lower": shown(b["lower"]), "upper": shown(b["upper"]), "count": b["count"]}
                    for b in histogram["bins"]
                ],
                "above": {"lower": shown(histogram["above"]["lower"]), "upper": None,
                          "count": histogram["above"]["count"]},
                "draws": histogram["draws"],
            },
        }
    return {
        "digest": row.charts_digest,
        "schema": row.schema,
        "basis": charts.get("basis"),
        "method": charts.get("method"),
        "lines": lines,
    }


#: The money units, as the canonical inputs spell them.
_MONEY_UNITS = frozenset(unit.value for unit in MONEY_UNITS)


def _sensitivity(card: FinancialValidityCard | None, shown: _Shown, units: Mapping[str, str] | None = None,
                 withheld: str | None = None) -> dict:
    if withheld is not None:
        return {"not_reported": withheld}
    if card is None or card.sensitivity is None:
        return {"not_reported": "no sensitivity analysis is recorded for this result"
                if card is None else "a refused run has nothing to analyse"}
    units = units or {}
    analysis = card.sensitivity
    tornado = []
    for entry in analysis.get("ranked", []):
        swing = entry.get("swing")
        # A money parameter's quantiles are money: at the minor unit, as every amount
        # the report states (review round 1, LOW-3); any other's as the analysis has them.
        quantile = shown if units.get(entry.get("name")) in _MONEY_UNITS else (lambda value: value)
        tornado.append(
            {
                **{k: v for k, v in entry.items() if k != "swing"},
                "swing": None
                if swing is None
                else {
                    "p10": quantile(swing["p10"]), "p50": quantile(swing["p50"]), "p90": quantile(swing["p90"]),
                    "low_outcome": shown(swing["low_outcome"]), "high_outcome": shown(swing["high_outcome"]),
                },
            }
        )
    baseline = analysis.get("swing_baseline") or {}
    return {
        "digest": card.sensitivity_digest,
        "method": analysis.get("method"),
        "basis": analysis.get("basis"),
        "output": "gross_cash",
        "output_varies": analysis.get("output_varies"),
        "baseline": {"outcome": shown(baseline.get("outcome")), "frequency_at": baseline.get("frequency_at")},
        "tornado": tornado,
        "fixed": analysis.get("fixed"),
        "not_in_gross_cash": analysis.get("not_in_gross_cash"),
        "per_occurrence": analysis.get("per_occurrence"),
        "statements": analysis.get("statements"),
    }


#: The card's fields the report carries as they are (none holds an amount of loss).
_CARD_FIELDS = (
    "confidence_grade",
    "customer_specific_share",
    "benchmark_derived_share",
    "expert_estimated_share",
    "last_calibrated",
    "data_freshness",
    "system_fingerprint",
    "technical_evidence",
    "unknown_variables",
    "reproduction",
)


def _model(card: FinancialValidityCard | None) -> dict | None:
    """The model release the card records (section 26.5): its version token and build
    digest; ``None`` where no card is recorded."""
    if card is None:
        return None
    model = card.card.get("fields", {}).get("model_version") or {}
    return {"version": model.get("version"), "build_digest": model.get("build_digest")}


def _card(card: FinancialValidityCard | None, unverified: bool = False) -> dict:
    if unverified:
        return {"not_reported": "the Validity Card recorded for this result does not verify against its digest, its "
                "grade or its result: it counts as no card, and the result is not graded"}
    if card is None:
        return {"not_reported": "no Validity Card is recorded for this result: it is not graded"}
    fields = card.card.get("fields", {})
    return {
        "digest": card.card_digest,
        "schema": card.schema,
        "issued_at": card.issued_at.isoformat(),
        "grade": card.card["confidence_grade"],
        "model_version": _model(card),
        "reviewer_status_at_issue": card.card.get("reviewer_status"),
        "fields": {name: fields.get(name) for name in _CARD_FIELDS},
        "statement": "the card's figures and most sensitive variables are this report's summary and tornado, at the "
        "minor unit; the whole card is the stored record its digest names",
    }


def _receipt(receipt: FinancialExposureReceipt | None) -> dict:
    if receipt is None:
        return {"not_reported": "no Financial Exposure Receipt is recorded for this result"}
    return {
        "receipt_id": receipt.receipt_id,
        "key_id": receipt.key_id,
        "generated_at": receipt.generated_at.isoformat(),
        "document_digest": canonical_digest(receipt.document),
        "validity_card_digest": (receipt.document.get("validity_card") or {}).get("digest"),
        "verified": False,
        "statement": "a reference, not verified by this report: the signature is verified against the engine's "
        "published keyring (receipt_service.verify_stored_receipt)",
    }


def served_snapshots(scenario: FinancialScenario) -> dict:
    """The scenario version's source snapshots with their content hashes recomputed
    from the stored rows, or why they are not reported (``source_snapshot_mismatch``)."""
    from .receipt_service import ReceiptRefused, source_snapshots

    try:
        return {"snapshots": source_snapshots(scenario)}
    except ReceiptRefused as refused:
        return {"not_reported": f"{refused.code}: {refused.detail}"}


def _currency_bridge(result: SimulationResult, build: ScenarioBuild | None, code: str, failed: list[str]) -> dict:
    """The run's valuation date and the normalization record of each figure it
    converted (section 30), from stored values only, never recomputed: the date is
    the build's as-of date, or for a version with no build the latest as-of date of
    the components its stored inputs hold, read only where they still give their
    digest; ``conversions`` is the record of each figure the build normalized as the
    stored inputs hold it, each served by :func:`served_conversion` (:data:`CONVERTED`),
    never from inputs that no longer give their digest; empty for a run whose build
    normalized nothing (:data:`NO_CONVERSION`)."""
    valuation: dict = {"valuation_date": None, "valuation_date_from": None}
    if build is not None:
        valuation = {"valuation_date": build.as_of.isoformat(), "valuation_date_from": VALUATION_FROM_BUILD}
    elif "input_digest" in failed:
        valuation["not_reported"] = (
            f"{STORED_ROW_UNVERIFIED}: the stored inputs no longer give the run's input digest, and the version has "
            "no build to read the valuation date from"
        )
    else:
        dates = sorted(
            component["as_of"]
            for event in (result.inputs.get("events") or [])
            for component in (event.get("components") or [])
            if isinstance(component.get("as_of"), str)
        )
        if dates:
            valuation = {"valuation_date": dates[-1], "valuation_date_from": VALUATION_FROM_INPUTS}
        else:
            valuation["not_reported"] = "the version has no build, and its stored inputs hold no component's as-of date"
    held = None if "input_digest" in failed else (result.inputs or {}).get("normalizations")
    if held:
        return {**valuation, "reporting_currency": code, "conversions": [served_conversion(r) for r in held],
                "statement": CONVERTED}
    if "input_digest" in failed and (result.inputs or {}).get("normalizations"):
        # Never served from inputs that no longer give their digest.
        return {**valuation, "reporting_currency": code, "conversions": [], "statement": CONVERTED,
                "conversions_not_reported": (
                    f"{STORED_ROW_UNVERIFIED}: the stored inputs no longer give the run's input digest")}
    return {**valuation, "reporting_currency": code, "conversions": [], "statement": NO_CONVERSION}


def served_conversion(record: Mapping) -> dict:
    """One figure's normalization record as the bridge serves it (the section-28
    audit's T7, as a portfolio serves a member's normalisation): as stored where every
    source it read, and every source a conflict names, may be redistributed (``open``,
    ``customer``); otherwise each point's record with every raw rate and index value,
    and every number made from them, withheld (provenance only), and so the
    normalized figures. The stored inputs keep the whole record; the figures stand."""
    from .portfolio import served_normalization

    policy = {"sources": list(record.get("sources") or [])}
    points, withheld = {}, None
    for name, point in sorted((record.get("points") or {}).items()):
        served = served_normalization({"record": point}, policy)
        points[name] = served["record"]
        withheld = withheld or served.get("withheld")
    entry = {**record, "points": points}
    if withheld is not None:
        normalized = dict(record.get("normalized") or {})
        normalized.update({point: None for point in ("low", "base", "high")})
        entry.update(
            normalized=normalized,
            conflicts=[c for c in (points.get("base") or {}).get("conflicts") or []],
            withheld=withheld,
        )
    return entry


def _unknowns(result: SimulationResult, events: list[dict], failed: list[str]) -> list[dict]:
    found = []
    for event in events:
        for component in event["components"]:
            if component["status"] != "estimated":
                found.append(
                    {
                        "kind": "component",
                        "id": f"{event['event_key']}/{component['component_id']}",
                        "reason": component["unknown_reason"],
                        "missing": component["missing"],
                    }
                )
    if result.status != SIMULATION_COMPLETED:
        found.append({"kind": "refusal", "id": result.refusal_code, "reason": result.refusal_detail, "missing": []})
    if failed:
        found.append({"kind": "integrity", "id": STORED_ROW_UNVERIFIED, "reason": _unverified(failed),
                      "missing": list(failed)})
    return found


def _unverified(failed: list[str]) -> str:
    return (
        f"{STORED_ROW_UNVERIFIED}: the stored rows fail {', '.join(failed)}: a row no longer gives its digest, or "
        "names another result; served as a refusal"
    )


# ------------------------------------------------------------------ the report


def build_report(result: SimulationResult) -> dict:
    """The report of ``result``, with its digest: see the module's rules."""
    scenario = FinancialScenario.objects.get(pk=result.scenario_id)
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    deployment_uuid = str(Deployment.objects.get(pk=scenario.deployment_id).uuid)
    code = build.currency if build is not None else result.inputs.get("reporting_currency")
    shown = _Shown(code)
    card = FinancialValidityCard.objects.filter(simulation=result).first()
    receipt = FinancialExposureReceipt.objects.filter(simulation=result).first()
    charts = SimulationCharts.objects.filter(simulation=result).first()
    # Every stored row checked before it is served (review round 1, MEDIUM-1).
    failed = stored_row_failures(result, card, charts, scenario)
    card_unverified = card is not None and any(check in CARD_CHECKS for check in failed)
    if card_unverified:
        card = None  # a card that fails a check counts as no card
    if any(check in CHARTS_CHECKS for check in failed):
        charts = None
    completed = result.status == SIMULATION_COMPLETED
    figures = completed and not failed
    grade = card.card["confidence_grade"] if card is not None else None
    withheld = _unverified(failed) if failed else None
    why = banner_reason(result, grade, failed)
    events = _loss_events(scenario, build, shown, figures=figures)
    record = result.record if completed and "result_digest" not in failed else None
    if not completed:
        refusal = {"code": result.refusal_code, "detail": result.refusal_detail}
    elif failed:
        refusal = {"code": STORED_ROW_UNVERIFIED, "detail": withheld}
    else:
        refusal = None
    if figures:
        summary = _summary(result, shown)
    elif failed:
        summary = {"not_reported": withheld}
    else:
        summary = {"not_reported": f"refused: {result.refusal_code}"}
    units = {name: (entry or {}).get("unit") for name, entry in (result.inputs.get("parameters") or {}).items()} \
        if "input_digest" not in failed else {}
    # A residual run under a remediation option (section 28) is marked at the top
    # level, and is excluded from every total whatever its grade: it is the scenario
    # as the option would leave it, never its exposure.
    residual_of = None
    if result.remediation_id is not None:
        option = RemediationOption.objects.filter(pk=result.remediation_id).values_list("uuid", "option_digest").first()
        residual_of = {
            "option": None if option is None else str(option[0]),
            "option_digest": None if option is None else option[1],
            "statement": "a residual run under a remediation option: the scenario as the option would leave it, "
            "never its exposure, and excluded from every total",
        }
    report = {
        "schema": REPORT_SCHEMA,
        "scenario": _scenario_part(scenario, deployment_uuid),
        "build": _build_part(build),
        "simulation": {
            "uuid": str(result.uuid),
            "status": result.status,
            "seed": result.seed,
            "draws": result.draws,
            "severe_percentile": result.severe_percentile,
            "basis": None if record is None else record["basis"],
            "input_digest": result.input_digest,
            "result_digest": result.result_digest or None,
            "outcomes_sha256": None if record is None else record["outcomes_sha256"],
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "recorded_at": result.recorded_at.isoformat(),
        },
        "versions": result.versions,
        "model": _model(card),
        "source_snapshots": served_snapshots(scenario),
        "currency": {"code": code, "minor_unit": shown.minor_unit, "rounding": ROUNDING},
        "currency_bridge": _currency_bridge(result, build, code, failed),
        "status": result.status,
        "refusal": refusal,
        "integrity": {"verified": not failed, "checks": list(INTEGRITY_CHECKS), "failed": list(failed)},
        "grade": grade,
        "banner": None if why is None else UNKNOWN_BANNER,
        "excluded_from_totals": why is not None or residual_of is not None,
        "banner_reason": why,
        "residual_of": residual_of,
        "loss_events": events,
        "parameters": _parameters(result.inputs) if "input_digest" not in failed else {
            "not_reported": f"{STORED_ROW_UNVERIFIED}: the stored inputs no longer give the run's input digest"
        },
        "summary": summary,
        "charts": _charts(charts, result, shown, withheld),
        "sensitivity": _sensitivity(card, shown, units, withheld),
        "validity_card": _card(card, unverified=card_unverified),
        "receipt": _receipt(receipt),
        "limitations": list(LIMITATIONS),
        "unknowns": _unknowns(result, events, failed),
    }
    report["digest"] = digest_of(report)
    return report


# ------------------------------------------------------------------ the scenario


def scenario_document(scenario: FinancialScenario) -> dict:
    """A scenario version as its GET serves it: the scenario and its build; every
    parameter it reads with its provenance (its parent, source, evidence, dates,
    stated distribution and what reads it); its validity, each simulation result
    with its grade; and its evidence as SPINE ids, never copies."""
    from .receipt_service import spine_evidence

    deployment_uuid = str(Deployment.objects.get(pk=scenario.deployment_id).uuid)
    build = ScenarioBuild.objects.filter(scenario=scenario).first()
    rows = list(FinancialParameter.objects.filter(scenario=scenario).order_by("name", "id"))
    version = None
    if build is not None:
        version = CustomerParameterSet.objects.get(pk=build.parameter_set_id)
        rows += list(FinancialParameter.objects.filter(parameter_set=version).order_by("name", "id"))
    by_uuid = {str(row.uuid): row for row in rows}
    read_by: dict[str, list[str]] = {}
    for event in LossEvent.objects.filter(scenario=scenario).order_by("event_key", "id"):
        for component in LossComponent.objects.filter(loss_event=event).order_by("id"):
            for name, cited in sorted(component.cited_parameters.items()):
                read_by.setdefault(cited, []).append(f"{event.event_key}/{component.component_key}.{name}")
    for row in rows:
        for contributor in row.derived_from:
            read_by.setdefault(contributor, []).append(f"derived:{row.name}")
        if row.scenario_id is not None and row.name == "frequency":
            read_by.setdefault(str(row.uuid), []).append("frequency")
    policy = None if version is None else run_normalization.policy_of(build)
    for figure in run_normalization.stored(scenario):
        read_by.setdefault(str(figure.native.uuid), []).append(f"normalized:{figure.normalized.name}")
    if policy is not None:
        terms = [("deductible", policy.deductible), ("limit", policy.limit)]
        terms += [(f"sublimit:{family}", term) for family, term in sorted(policy.sublimits.items())]
        if policy.waiting_period_hours is not None:
            terms.append(("waiting_period_hours", policy.waiting_period_hours))
        for role, term in terms:
            read_by.setdefault(term.parameter_id, []).append(f"policy.{role}")

    def parameter(row: FinancialParameter) -> dict:
        parent = (
            {"scenario": str(scenario.uuid)}
            if row.scenario_id is not None
            else {"parameter_set": {"set_key": version.set_key, "version": version.version}}
        )
        return {
            "uuid": str(row.uuid),
            "name": row.name,
            "parent": parent,
            "unit": row.unit,
            "currency": row.currency or None,
            "low": row.low,
            "base": row.base,
            "high": row.high,
            "source_type": row.source_type,
            "evidence_ref": row.evidence_ref,
            "effective_date": row.effective_date.isoformat(),
            "fresh_until": row.fresh_until.isoformat() if row.fresh_until else None,
            "distribution": row.distribution,
            "derived_from": [by_uuid[u].name if u in by_uuid else u for u in row.derived_from],
            "read_by": sorted(read_by.get(str(row.uuid), [])),
        }

    results = []
    # The scenario's own runs: a residual run (section 28) is the ROI route's.
    for result in SimulationResult.objects.exposure_runs().filter(scenario=scenario).order_by("id"):
        card = FinancialValidityCard.objects.filter(simulation=result).first()
        receipt = FinancialExposureReceipt.objects.filter(simulation=result).first()
        results.append(
            {
                "uuid": str(result.uuid),
                "seed": result.seed,
                "draws": result.draws,
                "severe_percentile": result.severe_percentile,
                "status": result.status,
                "refusal_code": result.refusal_code or None,
                "recorded_at": result.recorded_at.isoformat(),
                "grade": verified_grade(card, result),
                "card_verified": None if card is None else verified_grade(card, result) is not None,
                "card_digest": None if card is None else card.card_digest,
                "charts": SimulationCharts.objects.filter(simulation=result).exists(),
                "receipt_id": None if receipt is None else receipt.receipt_id,
            }
        )
    effects = [
        {
            "effect_key": effect.effect_key,
            "origin": effect.origin,
            "observed_effect": effect.observed_effect or None,
            "observation": effect.observation or None,
            "spine_effect": effect.spine_effect or None,
            "asset": effect.asset,
            "loss_event": LossEvent.objects.get(pk=effect.loss_event_id).event_key,
        }
        for effect in CausalEffect.objects.filter(scenario=scenario).order_by("effect_key", "id")
    ]
    findings = [
        {"finding": link.finding, "effect_key": CausalEffect.objects.get(pk=link.effect_id).effect_key,
         "role": link.role}
        for link in EffectFinding.objects.filter(effect__scenario=scenario).order_by("finding", "id")
    ]
    frequency = next((row.name for row in rows if row.name == "frequency"), None)
    return {
        "schema": SCENARIO_SCHEMA,
        "scenario": _scenario_part(scenario, deployment_uuid),
        "build": _build_part(build),
        "parameters": [parameter(row) for row in rows],
        "frequency": frequency,
        "validity": {
            "simulations": results,
            "statement": "each simulation result with the grade its Validity Card's document states, where the card "
            "verifies; a result with none, or with one that does not verify, is not graded",
        },
        "evidence": {
            "spine": spine_evidence(scenario),
            "effects": effects,
            "findings": findings,
            "statement": "SPINE ids only: the evidence itself is SPINE's, never copied here",
        },
    }


# ------------------------------------------------------------------ the deployment's scenarios


def templates_of(scenarios) -> dict[int, list[dict]]:
    """Each of ``scenarios``' templates, as its causal effects record them (the id and
    version each effect was assigned to, section 24.3), by scenario id: one read for
    the whole page. A version with no effect (one not built) has none."""
    found: dict[int, list[dict]] = {}
    rows = (
        CausalEffect.objects.filter(scenario_id__in=[scenario.pk for scenario in scenarios])
        .values_list("scenario_id", "template_id", "template_version")
        .order_by("scenario_id", "template_id", "template_version")
        .distinct()
    )
    for scenario_id, template_id, version in rows:
        found.setdefault(scenario_id, []).append({"template_id": template_id, "version": version})
    return found


def scenario_entry(scenario: FinancialScenario, templates: list[dict]) -> dict:
    """One line of a deployment's scenario list (section 30): the version, its
    ``templates``, its latest EXPOSURE run's status (:func:`latest_exposure_run`: a
    residual run is never listed) and that run's standing under the banner rule --
    the grade, the banner, ``excluded_from_totals`` and why -- as the events route
    serves it (:func:`standing`). Reads rows, hashes them and runs nothing else."""
    result = latest_exposure_run(scenario)
    return {
        "uuid": str(scenario.uuid),
        "title": scenario.title,
        "recorded_at": scenario.recorded_at.isoformat(),
        "supersedes": None if scenario.supersedes_id is None else str(scenario.supersedes.uuid),
        "templates": templates,
        "latest_exposure_run": None
        if result is None
        else {
            "uuid": str(result.uuid),
            "status": result.status,
            "refusal_code": result.refusal_code or None,
            "recorded_at": result.recorded_at.isoformat(),
        },
        **_standing_of(scenario, result),
    }


__all__ = [
    "FIGURES",
    "GRADES_FOR_TOTALS",
    "INTEGRITY_CHECKS",
    "LIMITATIONS",
    "LINES",
    "NO_CONVERSION",
    "NO_RESULT",
    "REPORT_SCHEMA",
    "REPORT_SCHEMAS",
    "REPORT_SCHEMA_V1",
    "SCENARIO_SCHEMA",
    "STORED_ROW_UNVERIFIED",
    "UNKNOWN",
    "UNKNOWN_BANNER",
    "VALUATION_FROM_BUILD",
    "VALUATION_FROM_INPUTS",
    "banner_reason",
    "build_report",
    "canonical_bytes",
    "digest_of",
    "latest_exposure_run",
    "may_be_totalled",
    "scenario_document",
    "scenario_entry",
    "stands",
    "served_snapshots",
    "standing",
    "stored_row_failures",
    "templates_of",
    "verified_grade",
    "verifies",
]
