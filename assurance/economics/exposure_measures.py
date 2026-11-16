"""Every figure of loss or exposure in the economic-exposure report as a typed measure
(roadmap AT-6; ``docs/economics/spec-v1.md``, section 38.2).

The report (:mod:`.exposure_report`) shows figures of loss and exposure. Each is held here as a
:class:`mythos_core.measures.Measure`: its kind (one of the core's eight, never one
of this service's own), its amount as the core's ``Money`` (a ``Decimal`` at the
currency's minor unit, in one reportable currency), the period it is for, and what
it rests on (a ``SourceReference``: a snapshot id and its content hash). Nothing is
typed by default: a figure the core refuses, or whose kind this service cannot
establish, is a :class:`Figure` with no measure and the reason, and reads so.

- **What the report holds.** Every figure it shows of a scenario run, of a residual
  run and of the deployment's portfolio is a statistic of a simulated distribution
  (a mean, a percentile, an expected shortfall): ``modeled_exposure``. It is never a
  ``confirmed_loss`` or any other booked kind: no row of economics records a booked
  figure.
- **The amount is the report's own, unchanged.** A measure is built from the text
  the report already prints (the stored amount at the minor unit); nothing is
  rounded, padded or converted here, and the core refuses an amount that is not at
  the currency's minor unit.
- **The period is the valuation day alone.** A modelled figure is valued as of one day
  (the run's valuation date; the portfolio's). A simulated year is not a calendar
  year and the stored rows state no first or last day for it, so the period is that
  one day, first and last. A run with no valuation date has no period: its figures
  are not measures, and say why.
- **What a figure rests on** is the stored inputs of the model run that computed it:
  ``simulation-inputs:<run>`` or ``portfolio-inputs:<portfolio>`` with the run's
  input digest, which the integrity checks already hold the stored rows to.
- **An assumption is not a measure.** A parameter the run reads (an amount, or an
  amount per unit, per hour or per year) is an input as someone stated it, not a figure
  of loss or exposure: the report lists it with its assumptions, as recorded, with no
  kind (:data:`ASSUMPTIONS_ARE`), and it is never a gap for having none.
- **Totals go through the core** (:func:`total`): the one place this report may add
  figures is ``mythos_core.measures.total``, which refuses two kinds, two currencies
  and any two modelled exposures. The deployment total is never made here: it is the
  portfolio's own figure, typed (:func:`portfolio_run`).
- **Side by side** (:func:`beside`): two figures the report sets beside each other
  are a ``mythos_core.measures.SideBySide``, with the core's reason they do not add.

Pure: no Django, no database, no clock. Nothing here is on a stop path: it is
imported only by :mod:`.exposure_report`, which is imported inside its view.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from mythos_core import measures

#: What each of the core's eight kinds means, in the core's words (the table of
#: ``mythos_core.measures``' own docstring;
#: ``tests/test_every_exposure_figure_says_its_kind.py`` holds each line to it).
KIND_MEANS: dict[str, str] = {
    measures.CONFIRMED_LOSS: "value lost, as the one who lost it confirms it",
    measures.REMEDIATION_EXPENSE: "money spent responding and restoring: incident and exceptional costs, as booked",
    measures.REVENUE_DEFERRAL: "revenue the incident delayed or held back: deferred, which is not lost",
    measures.MODELED_EXPOSURE: "a figure a model computed for a scenario: never booked, and never added to another",
    measures.INSURANCE_PROMISED: "cover stated, committed or claimed, and not yet paid",
    measures.INSURANCE_RECEIVED: "insurance money actually received",
    measures.FUNDS_FROZEN: "assets held where they are, and not yet returned",
    measures.FUNDS_RETURNED: "assets actually returned to those they were taken from",
}
#: What a figure's kind reads where it cannot be established. Not a kind of the core.
UNKNOWN = "unknown"
#: The rule, as the report states it.
RULE = (
    "every figure of loss or exposure in this report is held as a measure of mythos_core.measures: its kind, its "
    "money in one currency at the minor unit, the period it is for and the snapshot it rests on. Figures of two kinds "
    "are never added, nor figures in two currencies, at any rate; a modelled exposure is never added to any figure, "
    "another modelled exposure included: a total of modelled exposures is a model run's own to state. A figure whose "
    "kind is not established reads unknown, with the reason, and is never shown under a default kind"
)
PERIOD_RULE = (
    "a modelled figure is for its valuation day alone, first and last day the same: a simulated year is not a "
    "calendar year, and the stored rows state no other day for it"
)
BASIS_RULE = (
    "a modelled figure rests on the stored inputs of the model run that computed it (simulation-inputs for a "
    "scenario's run, portfolio-inputs for the portfolio's), named by that run's id, with that run's input digest, "
    "which the integrity checks hold the stored rows to"
)
#: What the report says of its assumptions: inputs as stated, never measures (no kind, no gap).
ASSUMPTIONS_ARE = (
    "inputs the model reads, as the customer, an expert, a benchmark or an observation states them: not measures of "
    "loss or exposure; each is shown as recorded, with no kind, and is never added to any figure"
)
#: The kind every figure of a model run is, with the core's meaning of it.
MODELED = f"{measures.MODELED_EXPOSURE}: {KIND_MEANS[measures.MODELED_EXPOSURE]}"
NO_PERIOD = "it has no period: the run's valuation date is not measured"
NOT_SUMMED = "the report adds nothing"


@dataclass(frozen=True)
class ModelRun:
    """What every figure of one model run shares: its currency, its valuation day,
    the snapshot it rests on and where it is recorded."""

    currency: str
    valuation_date: str | None
    snapshot_id: str
    content_hash: str
    source: str


@dataclass(frozen=True)
class Figure:
    """One amount of money the report shows: where, under which label, the text it
    is shown as, its kind, and its measure -- or why it is not one."""

    section: str
    label: str
    shown: str
    kind: str
    measure: measures.Measure | None
    why: str | None

    def __post_init__(self) -> None:
        # Never a number under a default kind: a measure's kind is the figure's, and a
        # figure with neither a measure nor a reason is refused.
        if self.measure is not None and (type(self.measure) is not measures.Measure or self.measure.kind != self.kind
                                         or self.why is not None):
            raise ValueError("a figure's kind is its measure's, and a measure has no reason it is not one")
        if self.measure is None and (not self.why or self.kind not in (*measures.MEASURE_KINDS, UNKNOWN)):
            raise ValueError("a figure that is not a measure states why, under a kind of the core or unknown")
        if self.kind == UNKNOWN and self.measure is not None:
            raise ValueError("a figure of unknown kind is never a measure")


def scenario_run(built: dict) -> ModelRun:
    """The run a scenario version's report (:func:`report.build_report`) is of."""
    simulation = built["simulation"]
    return ModelRun(
        currency=built["currency"]["code"],
        valuation_date=built["currency_bridge"].get("valuation_date"),
        snapshot_id=f"simulation-inputs:{simulation['uuid']}",
        content_hash=simulation["input_digest"],
        source=f"{built['schema']}:{simulation['uuid']}",
    )


def portfolio_run(served: dict) -> ModelRun:
    """The joint run a portfolio's document (:func:`portfolio.build_document`) is of:
    the deployment total's figures are its own, typed here and never recomputed."""
    held = served["portfolio"]
    return ModelRun(
        currency=served["currency"]["code"],
        valuation_date=held.get("valuation_date"),
        snapshot_id=f"portfolio-inputs:{held['uuid']}",
        content_hash=held["input_digest"],
        source=f"{served['schema']}:{held['uuid']}",
    )


def modeled(run: ModelRun, section: str, label: str, value: str) -> Figure:
    """A model run's figure, as a ``modeled_exposure`` measure built through the core:
    ``value`` is the amount exactly as the report prints it. Where the core refuses
    any part of it, or the run has no valuation date, the figure is not a measure and
    says why; its kind stays the model's, never another."""
    return held(measures.MODELED_EXPOSURE, run, section, label, value)


def held(kind: str, run: ModelRun, section: str, label: str, value: str) -> Figure:
    """A figure of ``kind`` (one of the core's eight), as a measure built through the
    core from ``value``, the amount exactly as it is served; or, where the core refuses
    any part of it or ``run`` has no valuation date, not a measure, with the reason, its
    kind kept."""
    shown = f"{run.currency} {value}"
    if run.valuation_date is None:
        return Figure(section, label, shown, kind, None, NO_PERIOD)
    try:
        measure = measures.Measure(
            kind=kind,
            amount=measures.Money(Decimal(value), run.currency),
            period=measures.Period(run.valuation_date, run.valuation_date),
            cumulative=False,
            basis=measures.SourceReference(run.snapshot_id, run.content_hash),
            source=run.source,
        )
    except measures.MeasureError as refused:
        return Figure(section, label, shown, kind, None, f"mythos_core.measures refuses it ({refused.code})")
    except (InvalidOperation, TypeError, ValueError):
        return Figure(section, label, shown, kind, None, "its amount is not a number")
    return Figure(section, label, shown, measure.kind, measure, None)


def not_established(section: str, label: str, shown: str, why: str) -> Figure:
    """A figure whose kind this service cannot establish: unknown, with the reason."""
    return Figure(section, label, shown, UNKNOWN, None, why)


def total(figures: list[Figure] | tuple[Figure, ...]) -> measures.Total:
    """The total of ``figures``, made by the core and nowhere else: one kind, one
    currency, one basis, no shared day, and never a modelled exposure
    (:class:`mythos_core.measures.MeasuresDoNotAdd` names the two that do not add). A
    figure that is not a measure is refused (``not_a_measure``), never read as zero."""
    return measures.total([figure.measure for figure in figures])


def why_not_added(figures: list[Figure] | tuple[Figure, ...]) -> str | None:
    """The code of the core's rule that refuses the total of ``figures``, or ``None``
    where the core would add them."""
    try:
        total(figures)
    except measures.MeasureError as refused:
        return refused.code
    return None


def beside(left: Figure, right: Figure) -> str:
    """Two figures set side by side (``mythos_core.measures.side_by_side``), each
    under its kind, and the core's reason they do not add. Never a sum or a
    difference."""
    pair = measures.side_by_side(left.measure, right.measure)
    (left_kind, one), (right_kind, other) = pair.labelled
    code = why_not_added((left, right))
    return (f"{left.section}, {left.label} ({left_kind}, {one.amount}) beside {right.section}, {right.label} "
            f"({right_kind}, {other.amount}): " + (NOT_SUMMED if code is None else f"they do not add ({code})"))


def said(figure: Figure) -> str:
    """One figure in words: its kind, money, period, basis and source, each as the
    core spells it; or its kind and why it is not a measure, with the text it is
    shown as."""
    if figure.measure is None:
        return f"{figure.kind}; not held as a measure: {figure.why}; shown as recorded: {figure.shown}"
    measure = figure.measure
    running = "cumulative" if measure.cumulative else "for that period alone"
    return (f"{measure.kind}; {measure.amount}; period {measure.period}, {running}; rests on {measure.basis}; "
            f"recorded in {measure.source}")


def served(figures: list[Figure]) -> list[dict]:
    """Every figure as data, in the order the report shows them."""
    held = []
    for figure in figures:
        entry: dict = {"section": figure.section, "label": figure.label, "shown": figure.shown, "kind": figure.kind}
        measure = figure.measure
        if measure is None:
            held.append({**entry, "measure": None, "why": figure.why})
            continue
        held.append({**entry, "why": None, "measure": {
            "kind": measure.kind,
            "amount": format(measure.amount.amount, "f"),
            "currency": measure.amount.currency,
            "period": {"start": measure.period.start, "end": measure.period.end},
            "cumulative": measure.cumulative,
            "basis": {"snapshot_id": measure.basis.snapshot_id, "content_hash": measure.basis.content_hash},
            "source": measure.source,
        }})
    return held
