"""Chart-ready series of a stored run (MVP step 6; ``docs/economics/spec-v1.md``,
section 27.4): for each line of the scenario -- its gross cash, its retained cash
under a policy, its market value where a market-value component is known -- the
annual loss exceedance curve at fixed probabilities (the owner's specification,
section 20) and a histogram.

Made on the run's OWN draws, as the sensitivity analysis is (section 26.1):
:func:`series` takes the scenario version as step 7b read it, and refuses unless its
canonical inputs give the run's input digest (``inputs_changed``) and its draws, made
again from the same seed and sub-streams, give the run's outcomes digest
(``result_not_reproduced``: another numpy or platform, section 23.8). The series are
of the line the run's summary is of: per simulated year where the run has a
frequency (basis ``annual_loss``), per occurrence otherwise.

- **The exceedance curve** at :data:`EXCEEDANCE_PROBABILITIES`: the loss a year (or
  an occurrence) exceeds with probability p is the line's quantile at 1 - p, step
  7a's type 7 quantile of the run's sorted draws, as its percentiles are. A point is
  reported only where the run has at least :data:`MIN_DRAWS_BEYOND` draws beyond it
  (n p >= 10); otherwise its loss is ``None`` and it says why: a tail the draws do
  not reach is never extrapolated.
- **The histogram**: :data:`HISTOGRAM_BINS` equal bins from zero to the line's
  :data:`HISTOGRAM_TOP` percentile, each bin's width rounded UP to the currency's
  minor unit (one minor unit at least), so every edge is a whole number of minor
  units; one open bin above the last edge holds the tail. A bin holds the draws
  ``lower <= x < upper``. The counts sum to the draws.

Floats inside, decimal strings outside, as step 7a's record: no float in the result.
Pure: no Django, no database, no clock.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from decimal import ROUND_CEILING, Decimal
from fractions import Fraction
from types import MappingProxyType

import numpy as np

from . import distributions as dist
from . import scenario_simulation as ss
from . import simulation as sim
from .currency import minor_units
from .money import decimal_text

#: The series' schema.
SCHEMA = "mythos.economics.charts/v1"
#: A change to how a series is made is a new version.
VERSION = 1
#: The probabilities the exceedance curve is read at: from a one-in-two year to a
#: one-in-a-thousand year.
EXCEEDANCE_PROBABILITIES = tuple(
    Decimal(p) for p in ("0.5", "0.2", "0.1", "0.05", "0.02", "0.01", "0.005", "0.002", "0.001")
)
#: The fewest draws a point of the curve needs beyond it (n p) to be reported.
MIN_DRAWS_BEYOND = 10
#: The histogram's bins below its top edge.
HISTOGRAM_BINS = 40
#: The percentile its top edge is at least: above it, one open bin.
HISTOGRAM_TOP = Decimal(99)
#: The lines a series is made of, in this order.
LINES = (ss.GROSS_CASH, ss.RETAINED_CASH, ss.MARKET_VALUE_LINE)

REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "inputs_changed": "the scenario's stored rows no longer give the run's canonical inputs",
        "result_not_reproduced": "the draws made again are not the run's (another numpy or platform)",
    }
)


class ChartsRefused(ValueError):
    """A series that cannot be made of the run. ``code`` is one of :data:`REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


def version_record() -> dict:
    """Everything a series depends on but the run: part of every record."""
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "exceedance_probabilities": [decimal_text(p) for p in EXCEEDANCE_PROBABILITIES],
        "min_draws_beyond": MIN_DRAWS_BEYOND,
        "histogram_bins": HISTOGRAM_BINS,
        "histogram_top_percentile": decimal_text(HISTOGRAM_TOP),
        "quantile": "type 7 (Hyndman and Fan), step 7a's, of the run's own sorted draws",
    }


def _noop(stage: str) -> None:
    """The default ``check_time``: no budget."""


def exceedance(ordered: np.ndarray) -> list[dict]:
    """The exceedance curve of ``ordered`` (sorted draws): for each probability, the
    loss exceeded with that probability, or why it is not reported."""
    n = ordered.size
    points = []
    for p in EXCEEDANCE_PROBABILITIES:
        expected_beyond = Fraction(p) * n
        if expected_beyond < MIN_DRAWS_BEYOND:
            points.append(
                {
                    "probability": decimal_text(p),
                    "loss": None,
                    "draws_beyond": None,
                    "not_reported": (
                        f"{n} draws hold {float(expected_beyond):g} beyond probability {decimal_text(p)}, fewer than "
                        f"{MIN_DRAWS_BEYOND}: a tail the draws do not reach is not extrapolated; run more draws"
                    ),
                }
            )
            continue
        loss = sim.quantile(ordered, 1 - Fraction(p))
        beyond = int(n - np.searchsorted(ordered, loss, side="right"))
        points.append(
            {"probability": decimal_text(p), "loss": dist.float_text(loss), "draws_beyond": beyond,
             "not_reported": None}
        )
    return points


def histogram(ordered: np.ndarray, currency: str) -> dict:
    """The histogram of ``ordered`` (sorted draws, at least zero) in ``currency``: see
    the module's rules."""
    n = ordered.size
    unit = Decimal(1).scaleb(-minor_units(currency))
    top = Decimal(dist.float_text(sim.quantile(ordered, Fraction(HISTOGRAM_TOP) / 100)))
    width = max((top / HISTOGRAM_BINS).quantize(unit, rounding=ROUND_CEILING), unit)
    edges = [width * i for i in range(HISTOGRAM_BINS + 1)]
    below = [int(np.searchsorted(ordered, float(edge), side="left")) for edge in edges]
    bins = [
        {"lower": decimal_text(edges[i]), "upper": decimal_text(edges[i + 1]), "count": below[i + 1] - below[i]}
        for i in range(HISTOGRAM_BINS)
    ]
    return {
        "width": decimal_text(width),
        "bins": bins,
        "above": {"lower": decimal_text(edges[-1]), "upper": None, "count": n - below[-1]},
        "draws": n,
    }


def series(
    si: ss.ScenarioInput,
    *,
    seed: int,
    draws: int,
    severe_percentile,
    input_digest: str,
    outcomes_sha256: str,
    check_time: Callable[[str], None] | None = None,
) -> dict:
    """The chart-ready series of ``si``'s run with ``seed`` and ``draws``, whose stored
    input digest and outcomes digest are given: a record of decimal strings. Refused
    unless the inputs and the draws are the run's."""
    check_time = check_time or _noop
    sim.check_seed(seed)
    sim.check_draws(draws)
    inputs = ss.canonical_inputs(si, severe_percentile=severe_percentile)
    if ss.digest_of(inputs) != input_digest:
        raise ChartsRefused("inputs_changed", f"{ss.digest_of(inputs)}, not {input_digest}")
    p = ss.plan(si)
    if p.frequency is None:
        ss._check_budget(p, draws, None)
    sample = ss._sample(p, seed, draws, check_time)
    reproduced = ss.outcomes_digest(ss._ordered_vectors(p, sample))
    if reproduced != outcomes_sha256:
        raise ChartsRefused("result_not_reproduced", f"{reproduced}, not {outcomes_sha256}")
    annual = p.frequency is not None
    vectors = sample.annual if annual else sample.scenario
    lines: dict[str, dict | None] = {}
    for line in LINES:
        vector = vectors.get(line)
        if vector is None:
            lines[line] = None
            continue
        if not np.isfinite(vector).all():
            raise sim.SimulationRefused("out_of_range", f"a {line} draw is too large to hold as a float")
        ordered = np.sort(vector, kind="stable")
        lines[line] = {"exceedance": exceedance(ordered), "histogram": histogram(ordered, si.currency)}
        del ordered
        check_time(f"charts {line}")
    del sample, vectors
    return {
        "schema": SCHEMA,
        "method": version_record(),
        "scenario_id": si.scenario_id,
        "seed": str(seed),
        "draws": draws,
        "input_digest": input_digest,
        "outcomes_sha256": outcomes_sha256,
        "basis": ss.ANNUAL_BASIS if annual else ss.PER_OCCURRENCE_BASIS,
        "reporting_currency": si.currency,
        "lines": lines,
    }


__all__ = [
    "EXCEEDANCE_PROBABILITIES",
    "HISTOGRAM_BINS",
    "HISTOGRAM_TOP",
    "LINES",
    "MIN_DRAWS_BEYOND",
    "REFUSALS",
    "SCHEMA",
    "VERSION",
    "ChartsRefused",
    "exceedance",
    "histogram",
    "series",
    "version_record",
]
