"""What the ROI document nets, and every amount of money in it as a typed measure
(roadmap AT-6b; ``docs/economics/spec-v1.md``, section 28.11).

The ROI document (:func:`.remediation_service.roi_document`, ``mythos.economics.roi/v2``)
sets the scenario as it is against the scenario as a remediation option would leave it.
Every amount of money it serves is held here through ``mythos_core.measures`` (the
figures of :mod:`.exposure_measures`), as one of the core's eight kinds, or says why it
is not one:

- **Each run's own figures** -- the current and the residual run's expected annual
  exposure, P90 and P95 -- are each a ``modeled_exposure`` of that run: its valuation
  day, the stored inputs of that run, that run's report.
- **The expected reduction** is a ``modeled_exposure`` too: never a booked kind, and
  never savings realised. It nets the current run's mean against the residual run's.
  The two runs draw the same years (one seed, the same streams; the document's
  ``current_pairing`` check holds it), so the difference of their means is the mean of
  the paired years' reductions: a figure of that pair of runs. It rests on the
  residual run's stored inputs, which hold the current run's (they are the residual
  run's without the remediation).
- **A difference of two percentiles** (``tail_reduction.<p>.difference_of_percentiles``,
  v1's ``reduction``) is not a percentile of the reduction, so not a figure the model
  computed: it is not held as a measure, its value is shown as before, and the two
  percentiles stand side by side.
- **The first-year investment** is ``remediation_expense``, the core's kind for an
  expense, and an ESTIMATE: the cost the option states (a cost is never observed), not
  money spent. It rests on the option's record and digest, so the core never adds it to
  a booked expense (``basis_mismatch``).
- **The ROI and the payback** are ratios, not money, so not measures: each sets the
  modelled reduction against the estimated cost, two kinds that never add or net.

Nothing here computes a figure: every amount is the text the document already serves.
Pure: no Django, no database, no clock. Nothing here is on a stop path: it is imported
only inside :func:`.remediation_service.roi_document`.
"""

from __future__ import annotations

from dataclasses import dataclass

from mythos_core import measures

from . import exposure_measures as em

#: What each figure of the ROI document nets, or sets against what (``nets``).
REDUCTION_IS = (
    "the current run's expected annual exposure less the residual run's: the two runs draw the same years (one seed, "
    "the same streams), so it is the mean of the paired years' reductions, a modelled figure (modeled_exposure); "
    "never booked, and never savings realised"
)
DIFFERENCE_IS = (
    "the current run's percentile less the residual run's: a difference of two percentiles, not a percentile of the "
    "reduction, and not money saved. Percentiles never add or net (mythos_core.measures), so the two percentiles "
    "stand side by side and this difference is not held as a measure"
)
COST_IS = (
    "an estimate: the implementation cost and one year of the recurring cost as the option states them (a cost is "
    "never observed), not money spent. It is held as remediation_expense, the core's kind for an expense, resting on "
    "the option's record, so it never adds to a booked expense"
)
RATIO_IS = (
    "a ratio, not money, so not a measure: it sets the modelled reduction (modeled_exposure) against the estimated "
    "first-year cost (remediation_expense), two kinds that never add or net; decision support, not a return realised"
)
NEGATIVE_IS = (
    "below zero the reduction is an increase, and the core's money is unsigned: it is not held as a measure, and is "
    "shown as served"
)
PERIOD_IS = (
    "every figure is for the valuation day alone, the day the runs and the estimate they are set against are valued "
    "on: the stored rows state no other day for a simulated year, and the option states no day its cost is spent"
)
BASIS_IS = (
    "each run's figure rests on that run's stored inputs, with its input digest; the expected reduction on the "
    "residual run's, which hold the current run's; the estimated cost on the option's record, with its digest"
)
NETS: dict[str, str] = {
    "expected_reduction": REDUCTION_IS,
    "tail_reduction": DIFFERENCE_IS,
    "first_year_investment": COST_IS,
    "risk_adjusted_roi": RATIO_IS,
    "payback": RATIO_IS,
    "period": PERIOD_IS,
    "basis": BASIS_IS,
}
#: What a pair set side by side says (``side_by_side``).
BESIDE_IS = "set side by side, never added or netted: do_not_add is the core's reason they do not add"

#: The lines of the document, as its figures name them: the headline, and the gross
#: cash beside it under a policy.
LINES = ("headline", "gross_cash")
#: The labels each line's figures are held under, as the document's keys spell them.
CURRENT, RESIDUAL = "current_expected_annual_exposure", "residual_expected_annual_exposure"
REDUCTION = "expected_reduction"
INVESTMENT = "first_year_investment"
POINTS = ("low", "base", "high")
TAILS = ("p90", "p95")
#: The pairs set side by side, left and right, on each line.
PAIRS = (
    (CURRENT, RESIDUAL),
    (REDUCTION, f"{INVESTMENT}.base"),
    *((f"tail_reduction.{tail}.current", f"tail_reduction.{tail}.residual") for tail in TAILS),
)


@dataclass(frozen=True)
class Runs:
    """What each kind of figure of the document rests on."""

    current: em.ModelRun
    residual: em.ModelRun
    reduction: em.ModelRun
    option: em.ModelRun


def runs_of(current: dict, residual: dict, *, option: str, option_digest: str, option_currency: str,
            option_source: str, roi_schema: str) -> Runs:
    """The runs of ``current`` and ``residual`` (their reports, :func:`report.build_report`),
    the reduction between them (it rests on the residual run's inputs, and is published
    in the ROI document), and the option's estimate (its record and digest)."""
    now, after = em.scenario_run(current), em.scenario_run(residual)
    return Runs(
        current=now,
        residual=after,
        reduction=em.ModelRun(after.currency, after.valuation_date, after.snapshot_id, after.content_hash,
                              f"{roi_schema}:{residual['simulation']['uuid']}"),
        option=em.ModelRun(option_currency, after.valuation_date, f"remediation-option:{option}", option_digest,
                           option_source),
    )


def figures_of(figures: dict, runs: Runs) -> list[em.Figure]:
    """Every amount of money of the document's ``figures``, held as a measure or with
    the reason it is not one, in the order the document serves them."""
    held: list[em.Figure] = []
    for line in LINES:
        block = figures if line == "headline" else figures.get(line)
        if not isinstance(block, dict):
            continue

        def put(label: str, value, kind: str, run: em.ModelRun) -> None:
            if value is not None:
                held.append(em.held(kind, run, line, label, value))

        put(CURRENT, block.get(CURRENT), measures.MODELED_EXPOSURE, runs.current)
        put(RESIDUAL, block.get(RESIDUAL), measures.MODELED_EXPOSURE, runs.residual)
        reduction = block.get(REDUCTION)
        if isinstance(reduction, str) and reduction.startswith("-"):
            held.append(em.Figure(line, REDUCTION, f"{runs.reduction.currency} {reduction}",
                                  measures.MODELED_EXPOSURE, None, NEGATIVE_IS))
        else:
            put(REDUCTION, reduction, measures.MODELED_EXPOSURE, runs.reduction)
        for point in POINTS:
            put(f"{INVESTMENT}.{point}", (block.get(INVESTMENT) or {}).get(point), measures.REMEDIATION_EXPENSE,
                runs.option)
        for tail in TAILS:
            part = (block.get("tail_reduction") or {}).get(tail) or {}
            put(f"tail_reduction.{tail}.current", part.get("current"), measures.MODELED_EXPOSURE, runs.current)
            put(f"tail_reduction.{tail}.residual", part.get("residual"), measures.MODELED_EXPOSURE, runs.residual)
            if part.get("difference_of_percentiles") is not None:
                held.append(em.Figure(line, f"tail_reduction.{tail}.difference_of_percentiles",
                                      f"{runs.current.currency} {part['difference_of_percentiles']}",
                                      measures.MODELED_EXPOSURE, None, DIFFERENCE_IS))
    return held


def served(held: list[em.Figure]) -> list[dict]:
    """Every figure as data (:func:`.exposure_measures.served`), each saying whether it
    is an estimate of a cost."""
    return [{**entry, "estimate": entry["kind"] == measures.REMEDIATION_EXPENSE} for entry in em.served(held)]


def pairs_of(held: list[em.Figure]) -> list[dict]:
    """The pairs the document sets against each other, each a
    ``mythos_core.measures.SideBySide`` with the core's reason they do not add: never a
    sum or a difference. The gross-cash line's reduction is set against the one
    estimated cost, the headline's."""
    by = {(figure.section, figure.label): figure for figure in held if figure.measure is not None}
    pairs = []
    for line in LINES:
        for left, right in PAIRS:
            one = by.get((line, left))
            other = by.get((line, right)) or (by.get(("headline", right)) if right.startswith(INVESTMENT) else None)
            if one is None or other is None:
                continue
            (left_kind, _), (right_kind, _) = measures.side_by_side(one.measure, other.measure).labelled
            pairs.append({"line": line, "left": f"{one.section}.{one.label}", "right": f"{other.section}.{other.label}",
                          "kinds": [left_kind, right_kind], "do_not_add": em.why_not_added((one, other)),
                          "statement": BESIDE_IS})
    return pairs
